import customtkinter as CT
import sqlite3
from datetime import datetime
from PIL import Image, ImageTk
import os


def database_inherit(sql, t, values):
    connect = sqlite3.connect("storage_manager.db")
    c = connect.cursor()
    if values is None:
        c.execute(sql)
    elif len(values)>1:
        c.execute(sql, (values,))
    else:
        c.execute(sql, (values[0]))

    if str(t) == "return":
        return c.fetchone()

    elif str(t) == "commit":
        connect.commit()
    connect.close()


def logging_all(users_name, event):
    now = datetime.now()
    x = now.strftime("%d/%m/%Y %H:%M:%S")

    connect = sqlite3.connect("storage_manager.db")
    c = connect.cursor()
    c.execute("INSERT INTO logs(log_user, log_event, log_time_stamp) VALUES(?,?,?)", (users_name, event, x,))
    connect.commit()


class app(CT.CTk):
    def __init__(self, *args, **kwargs):
        CT.CTk.__init__(self, *args, **kwargs)

        self.title("storage manger")
        self.geometry("400x400")

        self.change=None

        if os.path.exists("storage_manager.db"):
            print("exists")

        elif not os.path.exists("storage_manager.db"):
            self.database = database_maker(self)

        self.main = storage_main(self)

        self.mainloop()

    def clear_all(self):
        for widget in CT.CTkFrame.winfo_children(self):
            widget.destroy()


class storage_main(CT.CTkFrame, app):
    def __init__(self, parent):
        CT.CTkFrame.__init__(self, parent)
        self.place(x=0, y=0, relwidth=1, relheight=1)

        logging_all("guest", "----------session start----------")

        super().clear_all()

        self.admin_check_var = CT.StringVar()
        self.username = CT.StringVar()
        self.password = CT.StringVar()

        self.new_menu = None
        self.main_logged = None
        self.register = None
        self.dictionary_change_windows = None

        self.GUI_constructor()

    def GUI_constructor(self):
        print("main gui constructed")
        CT.set_appearance_mode("system")
        CT.set_default_color_theme("blue")

        CT.CTkLabel(self, text="main frame", height=20, width=120).place(x=140, y=20)

        CT.CTkImage(Image.open(r"/home/inkon/Desktop/Coding/python_coding/Strorage_manager/revealed_eye.png"))

        CT.CTkEntry(self, textvariable=self.username, width=120, height=20).place(x=140, y=60)

        CT.CTkButton(self, text="admin", command=self.admin_check, width=60, height=20, hover_color="green").place(x=0, y=330)
        CT.CTkButton(self, text="login", command=self.login_pass, width=60, height=20, hover_color="green").place(x=170, y=140)
        CT.CTkButton(self, text="quit", command=self.delete_coms, width=60, height=20, hover_color="green").place(x=290, y=140)
        CT.CTkButton(self, text="register", command=self.register_pass, width=60, height=20, hover_color="green").place(x=50, y=140)

        self.reveal_password(0)

    def reveal_password(self, args):
        if args == 1:
            self.password.set(self.password.get())
            CT.CTkEntry(self, textvariable=self.password, width=120).place(x=140, y=90)
            img1 = CT.CTkImage(Image.open(r"/home/inkon/Desktop/Coding/python_coding/Strorage_manager/revealed_eye.png"))
            CT.CTkButton(self, image=img1, text="", width=20, command=lambda: self.reveal_password(0),fg_color="transparent").place(x=260, y=90)

        elif args == 0:
            print(self.password.get())
            CT.CTkEntry(self, textvariable=self.password, width=120, show="*").place(x=140, y=90)
            self.Unrevealed_eye = CT.CTkImage(Image.open(r"/home/inkon/Desktop/Coding/python_coding/Strorage_manager/eye.png"))
            CT.CTkButton(self, image=self.Unrevealed_eye, text="", width=20, command=lambda: self.reveal_password(1), fg_color="transparent").place(x=260, y=90)

    def register_pass(self):
        self.register = register_main(self)

    def delete_coms(self):
        self.master.destroy()

    def login_pass(self):
        username = self.username.get()
        password = self.password.get()
        fetch = database_inherit("SELECT username, password FROM users WHERE username=?", "return", username)
        if str(fetch[1]) == str(password):
            self.main_logged = logged_main(self)
            logging_all(username, "logging in")

        else:
            CT.CTkLabel(self, text="incorrect password", width=120).place(x=140, y=140)

    def admin_check(self):
        CT.CTkLabel(self, text="admin password", width=120).place(x=140, y=300)
        CT.CTkEntry(self, textvariable=self.admin_check_var, show="*", width=120, height=20).place(y=325, x=140)
        CT.CTkButton(self, text="enter", command=self.admin_pass_through, width=100, hover_color="green").place(x=150,                                                                                             y=350)
        logging_all("guest", "admin button pressed")

    def admin_pass_through(self):
        admin_check = self.admin_check_var.get()
        fetch = database_inherit("SELECT password FROM users where username=?", "return", "admin")
        if int(fetch[0]) == int(admin_check):
            self.new_menu = admin_main(self)
            logging_all("guest", "logging into admin")
        else:
            CT.CTkLabel(self, text="incorrect admin password", width=120).place(x=125, y=380)


class admin_main(CT.CTkFrame, app):
    def __init__(self, parent):
        CT.CTkFrame.__init__(self, parent)
        self.place(x=0, y=0, relwidth=1, relheight=1)

        super().clear_all()

        prev_window = storage_main

        self.change_window = None
        self.dict = None
        self.new_menu = None

        super().clear_all()

        CT.CTkLabel(self, text="admin_main").pack()
        CT.CTkButton(self, text="change_password", command=self.changing_admin_password).pack()
        CT.CTkButton(self, text="back", command=self.back_to_main).pack()

    def changing_admin_password(self):
        super().clear_all()

    def back_to_main(self):
        self.back = storage_main(self)
        self.back.focus()


class register_main(CT.CTkFrame, app):
    def __init__(self, parent):
        CT.CTkFrame.__init__(self, parent)
        self.place(x=0, y=0, relwidth=1, relheight=1)

        self.username_input = CT.StringVar()
        self.password_input = CT.StringVar()
        self.password = CT.StringVar()

        self.back = None

        self.Unrevealed_eye = None
        self.set_to_bool = None

        # r"/home/inkon/Desktop/Coding/python_coding/Strorage_manager/password_reveal.png

        self.GUI_const()

    def GUI_const(self):
        super().clear_all()

        CT.CTkLabel(self, text="register main", width=120).place(x=140, y=20)

        CT.CTkEntry(self, textvariable=self.username_input, width=120).place(x=140, y=70)

        self.reveal_password(0)

        CT.CTkButton(self, text="enter", command=self.enter_values, width=60).place(x=140, y=130)
        CT.CTkButton(self, text="back", command=self.back_to_main, width=60).place(x=200, y=130)

    def back_to_main(self):
        self.back = storage_main(self)
        self.back.focus()

    def reveal_password(self, args):
        if args == 1:
            self.password.set(self.password_input.get())
            CT.CTkEntry(self, textvariable=self.password).place(x=140, y=100)
            img1 = CT.CTkImage(Image.open(r"/home/inkon/Desktop/Coding/python_coding/Strorage_manager/revealed_eye.png"))
            CT.CTkButton(self, image=img1, text="", width=20, command=lambda: self.reveal_password(0),fg_color="transparent").place(x=260, y=100)

        elif args == 0:
            CT.CTkEntry(self, textvariable=self.password_input, width=120, show="*").place(x=140, y=100)
            self.Unrevealed_eye = CT.CTkImage(Image.open(r"/home/inkon/Desktop/Coding/python_coding/Strorage_manager/eye.png"))
            CT.CTkButton(self, image=self.Unrevealed_eye, text="", width=20, command=lambda: self.reveal_password(1), fg_color="transparent").place(x=260, y=100)

    def enter_values(self):
        username = self.username_input.get()
        password = self.password_input.get()
        fetch = database_inherit(
            "SELECT users.username, user_waitlist.username_wait FROM users, user_waitlist WHERE user_waitlist.username_wait=users.username",
            "return", None)
        self.set_to_bool = set(fetch)
        if str(username) in self.set_to_bool:
            CT.CTkLabel(self, text="this username is already taken")

        else:
            database_inherit("INSERT into user_waitlist(username_wait, password_wait) VALUES(?,?)", "commit",
                                     (username, password,))


class logged_main(CT.CTkFrame, app):
    def __init__(self, parent):
        CT.CTkFrame.__init__(self, parent)
        self.place(x=0, y=0, relwidth=1, relheight=1)

        self.item_name = CT.StringVar()
        self.item_kg = CT.StringVar()
        self.item_value = CT.StringVar()

        self.back = None

        self.main_GUI()

    def back_to_main(self):
        self.back = storage_main(self)

    def main_GUI(self):
        super().clear_all()

        CT.CTkLabel(self, text="login main").pack()

        CT.CTkButton(self, text="add item", command=self.add_item_pass).pack()
        CT.CTkButton(self, text="remove item", command=self.remove_item_pass).pack()
        CT.CTkButton(self, text="back", command=self.back_to_main).pack()

    def add_item_pass(self):
        super().clear_all()

        CT.CTkLabel(self, text="adding item main").pack()

        CT.CTkEntry(self, textvariable=self.item_name, width=120).place(x=140, y=90)
        CT.CTkEntry(self, textvariable=self.item_kg, width=60).place(x=140, y=130)
        CT.CTkEntry(self, textvariable=self.item_value, width=60).place(x=200, y=130)

        CT.CTkButton(self, text="enter", command=lambda: self.items("add"), width=60).place(x=140, y=160)
        CT.CTkButton(self, text="back", command=self.main_GUI, width=60).place(x=200, y=160)

    def remove_item_pass(self):
        super().clear_all()

        CT.CTkLabel(self, text="deleting items main").pack()

        CT.CTkEntry(self, textvariable=self.item_name, width=120).pack()

        CT.CTkButton(self, text="remove item", command=lambda: self.items("remove")).pack()
        CT.CTkButton(self, text="back", command=self.main_GUI).pack()

    def items(self, args):
        if args == "add":
            database_inherit("INSERT into items(item_name, item_value_kg, item_values) VALUES(?,?,?)",
                             "commit", (self.item_name.get(), self.item_kg.get(), self.item_value.get()))
        elif args == "remove":
            if isinstance(args, int):
                sql = "DELETE FROM items where item_ID=?"
            else:
                sql = "DELETE FROM items where item_name=?"
            print(args)
            database_inherit(sql, "commit", self.item_name.get())


class database_maker:
    def __init__(self, args):
        self.create_users()
        self.create_items()
        self.create_user_waitlist()
        self.create_logs()

    def create_users(self):
        conn = sqlite3.connect("storage_manager.db")
        c = conn.cursor()
        sql = """CREATE TABLE IF NOT EXISTS users(
        username        TEXT NOT NULL,
        password        TEXT NOT NULL);"""
        c.execute(sql)
        conn.commit()
        c.execute("INSERT INTO users(username,password) VALUES(?,?)", ("admin", 1,))
        conn.commit()

    def create_items(self):
        conn = sqlite3.connect("storage_manager.db")
        c = conn.cursor()
        sql = """CREATE TABLE IF NOT EXISTS items(
        itemID          INTEGER PRIMARY KEY AUTOINCREMENT,
        item_name       TEXT NOT NULL,
        item_value_kg   TEXT,
        item_values     TEXT NOT NULL);"""
        c.execute(sql)
        conn.commit()

    def create_user_waitlist(self):
        conn = sqlite3.connect("storage_manager.db")
        c = conn.cursor()
        sql = """CREATE TABLE IF NOT EXISTS user_waitlist(
        username_wait   TEXT NOT NULL,
        password_wait   TEXT NOT NULL);"""
        c.execute(sql)
        conn.commit()

    def create_logs(self):
        conn = sqlite3.connect("storage_manager.db")
        c = conn.cursor()
        sql = """CREATE TABLE IF NOT EXISTS logs(
        log_ID          INTEGER PRIMARY KEY AUTOINCREMENT,
        log_user        TEXT NOT NULL,
        log_event       TEXT NOT NULL,
        log_time_stamp  TEXT NOT NULL);"""
        c.execute(sql)
        conn.commit()


app()
