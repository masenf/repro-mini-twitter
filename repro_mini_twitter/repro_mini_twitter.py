import datetime
from typing import List, Optional

from passlib.context import CryptContext
import sqlalchemy
import sqlmodel

import reflex as rx


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class Post(rx.Model, table=True):
    title: str
    body: str
    user_id: int = sqlmodel.Field(foreign_key="user.id")
    update_ts: datetime.datetime = sqlmodel.Field(
        default=None,
        sa_column=sqlalchemy.Column(
            "update_ts",
            sqlalchemy.DateTime(timezone=True),
            server_default=sqlalchemy.func.now(),
        ),
    )

    user: Optional["User"] = sqlmodel.Relationship(back_populates="posts", sa_relationship_kwargs={"lazy": "selectin"})
    flags: Optional[List["Flag"]] = sqlmodel.Relationship(back_populates="post")

    @classmethod
    def from_form_data(cls, form_data: dict) -> "Post":
        return cls(
            id=form_data.pop("post_id", None),
            **form_data,
        )

    def create_or_edit(self, session: sqlmodel.Session, user: "User") -> "Post":
        if not self.id:
            # Create post
            self.user = user
            session.add(self)
            return self

        # Editing post
        post = session.get(Post, self.id)
        if post.user_id != user.id and not user.is_mod:
            raise ValueError("Only moderators can edit other users' posts.")
        post.set(
            title=self.title,
            body=self.body,
            update_ts=datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0),
        )
        session.add(post)
        return post

    @staticmethod
    def cond_is_flagged(post: "Post", c1: rx.Component, c2: rx.Component | None = None) -> rx.Component:
        return rx.cond(post.flags & post.flags.length() > 0, c1, c2)

    @staticmethod
    def render(post: "Post") -> rx.Component:
        return rx.box(
            rx.hstack(rx.heading(post.title)),
            rx.hstack(
                rx.cond(
                    post.user,
                    rx.text(f"by {post.user.username}", font_size="0.7em"),
                ),
                rx.spacer(),
                rx.text(post.update_ts, font_size="0.7em"),
            ),
            rx.text(post.body),
            mod_tools(post),
        )


class User(
    rx.Model,
    table=True,  # type: ignore
):
    """A local User model with bcrypt password hashing."""

    username: str = sqlmodel.Field(unique=True, nullable=False, index=True)
    password_hash: str = sqlmodel.Field(default="", nullable=False)
    enabled: bool = True
    is_mod: bool = False
    is_admin: bool = False

    posts: List[Post] = sqlmodel.Relationship(back_populates="user")

    @staticmethod
    def hash_password(secret: str) -> str:
        """Hash the secret using bcrypt.

        Args:
            secret: The password to hash.

        Returns:
            The hashed password.
        """
        return pwd_context.hash(secret)

    def verify(self, secret: str) -> bool:
        """Validate the user's password.

        Args:
            secret: The password to check.

        Returns:
            True if the hashed secret matches this user's password_hash.
        """
        return pwd_context.verify(
            secret,
            self.password_hash,
        )


class Flag(rx.Model, table=True):
    post_id: int = sqlmodel.Field(foreign_key="post.id")
    user_id: int = sqlmodel.Field(foreign_key="user.id")
    message: str

    post: Optional[Post] = sqlmodel.Relationship(back_populates="flags")
    user: Optional[User] = sqlmodel.Relationship()

    @classmethod
    def from_form_data(cls, form_data: dict) -> "Flag":
        return cls(
            post_id=form_data.pop("flag_post_id", None),
            message=form_data.pop("message", None),
        )

    def create(self, session: sqlmodel.Session, user: User):
        post = session.get(Post, self.post_id)
        if not post:
            raise ValueError("Post not found.")
        self.user_id = user.id
        session.add(self)


class State(rx.State):
    active_user: Optional[User] = None
    error_message: str = ""

    def logout(self):
        self.active_user = None
        self.reset()

    def _is_mod(self, session: sqlmodel.Session) -> bool:
        if self.active_user is not None:
            session.add(self.active_user)
            return self.active_user.is_mod
        return False


class LoginForm(rx.Base):
    username: str
    password: str
    is_mod: bool = False
    is_admin: bool = False

    def login_or_create(self, session: sqlmodel.Session) -> User:
        user = session.exec(User.select.where(User.username == self.username)).first()
        if user and not user.verify(self.password):
            raise ValueError("Incorrect username / password.")
        if user and self.is_mod and not user.is_mod:
            raise ValueError(f"User {user.username} is not a moderator.")
        if not user:
            user = User(username=self.username, password_hash=User.hash_password(self.password), is_mod=self.is_mod)
            session.add(user)
            session.commit()
            session.refresh(user)
        return user


class LoginState(State):
    login_modal_is_shown: bool = False
    login_modal_error_message: str = ""

    def login(self, form_data: dict):
        try:
            form = LoginForm(**form_data)
        except ValueError as e:
            self.login_modal_error_message = str(e)
            return
        with rx.session() as session:
            try:
                self.active_user = form.login_or_create(session)
            except ValueError as e:
                self.login_modal_error_message = str(e) 
                return
            self.login_modal_error_message = ""
            self.login_modal_is_shown = False
            return PostState.load_posts

    @classmethod
    def modal(cls) -> rx.Component:
        return rx.modal(
            header="Login",
            close_button="Close",
            body=rx.form(
                rx.vstack(
                    rx.text(cls.login_modal_error_message),
                    rx.input(placeholder="Username", id="username"),
                    rx.password(placeholder="Password", id="password"),
                    rx.checkbox("User is Moderator?", type_="checkbox", id="is_mod"),
                    rx.button("Submit", type_="submit"),
                ),
                on_submit=cls.login,
            ),
            is_open=cls.login_modal_is_shown,
            on_close=cls.set_login_modal_is_shown(False),
        )

    @classmethod
    def login_logout_button(cls) -> rx.Component:
        return rx.cond(
            cls.active_user,
            rx.button(f"Logout {cls.active_user.username}", on_click=State.logout),
            rx.button("Login", on_click=cls.set_login_modal_is_shown(True)),
        )
        

def hidden_input_with_ref(id_: str) -> rx.Component:
    hidden_input = rx.input(id=id_, type_="hidden")
    # Accessing the hidden field value on the frontend via refs is possible
    hidden_input_value = rx.Var.create(
        f"refs['{hidden_input.get_ref()}']?.current?.value",
        _var_is_local=False,
    )
    return hidden_input, hidden_input_value


class PostState(State):
    posts: List[Post] = []
    post_modal_is_shown: bool = False
    post_modal_error_message: str = ""

    def load_posts(self):
        if not self.active_user:
            return
        load_options = []
        with rx.session() as session:
            if self._is_mod(session):
                # only moderators can see the flags
                load_options.append(
                    sqlalchemy.orm.selectinload(Post.flags).options(
                        sqlalchemy.orm.selectinload(Flag.user),
                    ),
                )
            if self._is_mod(session):
                print("I'm a mod!")
            self.posts = session.exec(
                Post.select
                .options(*load_options)
                .limit(15)
                .order_by(Post.update_ts.desc())
            ).all()
        self.error_message = ""

    def new_post(self):
        self.post_modal_is_shown = True

    def edit_post(self, post_id: int):
        with rx.session() as session:
            post = session.get(Post, post_id)
        if not post:
            self.error_message = "Post not found."
            self.post_modal_is_shown = False
            yield
            return
        self.post_modal_is_shown = True
        yield
        return [
            rx.set_value("post_id", post.id),
            rx.set_value("title", post.title),
            rx.set_value("body", post.body),
        ]

    def delete_post(self, post_id: int):
        with rx.session() as session:
            if not self._is_mod(session):
                self.error_message = "Only moderators can delete posts."
                return

            post = session.get(Post, post_id)
            session.delete(post)
            session.commit()
        return PostState.load_posts

    def submit_post(self, form_data: dict):
        if not self.active_user:
            self.post_modal_error_message = "Please log in to post."
            return
        try:
            post = Post.from_form_data(form_data)
        except ValueError as e:
            self.post_modal_error_message = str(e)
            return
        with rx.session() as session:
            try:
                post.create_or_edit(session, self.active_user)
                session.commit()
            except ValueError as e:
                self.post_modal_error_message = str(e)
                return
        self.post_modal_error_message = ""
        self.post_modal_is_shown = False
        return PostState.load_posts

    @classmethod
    def edit_post_modal(cls) -> rx.Component:
        hidden_post_id_input, post_id_value = hidden_input_with_ref("post_id")
        return rx.modal(
            header=rx.cond(
                post_id_value,
                rx.text(f"Edit Post ({post_id_value})"),
                rx.text("New Post"),
            ),
            close_button="Close",
            body=rx.form(
                hidden_post_id_input,
                rx.vstack(
                    rx.text(cls.post_modal_error_message),
                    rx.input(placeholder="Title", id="title"),
                    rx.input(placeholder="Body", id="body"),
                    rx.button("Submit", type_="submit"),
                ),
                on_submit=cls.submit_post,
            ),
            is_open=cls.post_modal_is_shown,
            on_close=cls.set_post_modal_is_shown(False),
        )


class FlagState(State):
    flag_modal_is_shown: bool = False
    flag_modal_error_message: str = ""

    def submit_flag(self, form_data: dict):
        if not self.active_user:
            self.flag_modal_error_message = "Please log in to flag."
            return
        try:
            flag = Flag.from_form_data(form_data)
        except ValueError as e:
            self.flag_modal_error_message = str(e)
            return
        with rx.session() as session:
            try:
                flag.create(session, user=self.active_user)
                session.commit()
            except ValueError as e:
                self.flag_modal_error_message = str(e)
                return
        self.flag_modal_error_message = ""
        self.flag_modal_is_shown = False
        return PostState.load_posts

    def delete_flag(self, flag_id: int):
        with rx.session() as session:
            if not self._is_mod(session):
                self.error_message = "Only moderators can delete flags."
                return

            flag = session.get(Flag, flag_id)
            session.delete(flag)
            session.commit()
        return PostState.load_posts

    def show_flag_modal(self, post_id: int | None):
        self.flag_modal_is_shown = True
        yield
        if post_id is not None:
            return rx.set_value("flag_post_id", post_id)

    @classmethod
    def flag_post_button(cls, post: Post) -> rx.Component:
        hidden_post_id_input, post_id_value = hidden_input_with_ref("flag_post_id")
        return rx.fragment(
            rx.button("Flag", on_click=cls.show_flag_modal(post.id)),
            rx.modal(
                header=f"Flag Post ({post_id_value})",
                close_button="Close",
                body=rx.form(
                    hidden_post_id_input,
                    rx.vstack(
                        rx.text(cls.flag_modal_error_message),
                        rx.input(placeholder="Why is this content inappropriate?", id="message"),
                        rx.button("Submit", type_="submit"),
                    ),
                    on_submit=cls.submit_flag,
                ),
                is_open=cls.flag_modal_is_shown,
                on_close=cls.set_flag_modal_is_shown(False),
            ),
        )

    @classmethod
    def flags_accordion(cls, post: Post) -> rx.Component:
        def flag_row(flag: cls):
            return rx.hstack(
                rx.text(flag.message),
                rx.text(flag.user.username),
                rx.button("X", on_click=cls.delete_flag(flag.id), size="sm"),
            )

        return Post.cond_is_flagged(
            post,
            rx.accordion(
                rx.accordion_item(
                    rx.accordion_button("Flags 🏴‍☠️", rx.accordion_icon()),
                    rx.accordion_panel(rx.foreach(post.flags, flag_row)),
                ),
                allow_multiple=True,
            ),
        )


def mod_tools(post: Post):
    return rx.cond(
        State.active_user.is_mod,
        rx.fragment(
            rx.hstack(
                rx.button("Edit", on_click=PostState.edit_post(post.id)),
                rx.button("Delete", on_click=PostState.delete_post(post.id)),
            ),
            FlagState.flags_accordion(post),
        ),
        FlagState.flag_post_button(post),
    )


def index():
    return rx.fragment(
        rx.vstack(
            rx.heading("Welcome to the Mini Twitter!"),
            rx.text(State.error_message),
            LoginState.modal(),
            LoginState.login_logout_button(),
            rx.cond(
                State.active_user,
                rx.button("New Post", on_click=PostState.new_post),
            ),
            PostState.edit_post_modal(),
            rx.foreach(PostState.posts, Post.render),
        ),
    )

app = rx.App()
app.add_page(index, on_load=PostState.load_posts)
app.compile()