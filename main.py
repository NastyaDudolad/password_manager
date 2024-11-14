import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import hashlib
from pswd_mngr_db_proxy import *

db_proxy = DatabaseProxy(messagebox, MAIN_TABLE)
credentials_window_visibility = False


class Root:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Менеджер паролів")
        self.root.geometry("400x300")  # Розмір вікна

        # Створюємо фрейм для розташування елементів у центрі
        frame = tk.Frame(self.root, bg=COLOR1, padx=20, pady=20)
        frame.place(relx=0.5, rely=0.5, anchor="center")  # Центруємо фрейм

        # Лейбл для вводу пароля
        label = tk.Label(frame, text="Введіть пароль:", bg=COLOR1)
        label.pack(pady=10)

        # Поле для вводу пароля
        self.entry = tk.Entry(frame, width=30, show='*')
        self.entry.pack(pady=10)

        # Кнопка для перевірки пароля
        button = tk.Button(frame, text="Увійти", command=self.check_password)
        button.pack(pady=10)

        self.root.mainloop()

    # Функція для перевірки пароля
    def check_password(self):
        global credentials_window_visibility
        if not credentials_window_visibility:
            credentials_window_visibility = True
            entry_password = self.entry.get()  # Отримуємо введений пароль

            # Порівнюємо хеші введеного пароля та збереженого
            # if hashlib.md5(entry_password.encode('utf-8')).digest() == PASSWORD_HASH:
            #     open_credentials_window()  # Відкриваємо друге вікно
            # else:
            #     messagebox.showerror('Помилка', 'Неправильний пароль')

            # Відкриваємо друге вікно
            Credentials(self.root)


class Credentials:
    def __init__(self, root):
        self.id = 0

        credentials_window = tk.Toplevel(root)
        credentials_window.title("Логіни та паролі")
        credentials_window.configure(bg=COLOR1)

        # Створіть Frame для Treeview і Scrollbar
        frame = tk.Frame(credentials_window)
        frame.pack(padx=10, pady=10, fill="both", expand=True)

        tree = ttk.Treeview(frame, columns=("site", 'login', 'password'), show="headings", height=5)
        tree.heading("site", text="Сайт")
        tree.heading("login", text="Логін")
        tree.heading("password", text="Пароль")

        # Create a Scrollbar
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        data = db_proxy.get_records()
        # Виводимо логіни та паролі
        for j, cred in enumerate(data):
            tree.insert("", "end", values=(cred[1], cred[2], cred[3]))

        # Відображення Treeview
        tree.pack(padx=10, pady=10)

        def on_select(event):
            self.id = int(tree.focus()[1:])

        tree.bind('<<TreeviewSelect>>', on_select)

        # Кнопки
        tk.Button(credentials_window, text="Закрити", command=credentials_window.destroy).pack(pady=10)
        add_button = tk.Button(credentials_window,
                               text='Додати запис',
                               pady=10,
                               command=lambda: AddCredentialEntity(credentials_window)
                               )
        add_button.pack()

        edit_button = tk.Button(credentials_window,
                                text='Редагувати',
                                pady=10,
                                command=lambda: EditCredentialEntity(credentials_window, self.id, data))
        edit_button.pack()


class CredentialEntity:
    def __init__(self, window, title, btn_title):
        self.window = window
        self.title = title
        self.btn_title = btn_title

        # Створити вікно
        add_window = tk.Toplevel(self.window)
        add_window.title(self.title)
        add_window.geometry("300x250")

        # Поля для введення нових даних
        tk.Label(add_window, text="Сайт:").pack(pady=5)
        self.site_entry = tk.Entry(add_window)
        self.site_entry.pack(pady=5)

        tk.Label(add_window, text="Логін:").pack(pady=5)
        self.login_entry = tk.Entry(add_window)
        self.login_entry.pack(pady=5)

        tk.Label(add_window, text="Пароль:").pack(pady=5)
        self.password_entry = tk.Entry(add_window)
        self.password_entry.pack(pady=5)

        tk.Button(add_window, text=self.btn_title, command=self.process_data).pack(pady=10)

    # TODO: change the return type
    def perform_db_operation(self, site, login, password):
        raise Exception("You must override this method")

    def process_data(self):
        site = self.site_entry.get()
        login = self.login_entry.get()
        password = self.password_entry.get()

        if site and login and password:
            try:
                self.perform_db_operation(site, login, password)
            except ValueError:
                messagebox.showerror('Помилка', 'Будь ласка, введіть правильне значення')
            except Exception as e:
                messagebox.showerror('Помилка', e)
        else:
            messagebox.showwarning('Попередження', 'Будь ласка, заповніть всі поля.')


class AddCredentialEntity(CredentialEntity):
    def __init__(self, window):
        super().__init__(window, 'Додавання користувача', 'Додати')

    def perform_db_operation(self, site, login, password):
        db_proxy.add_record(site, login, password)
        messagebox.showinfo('Успіх', 'Користувач доданий до бази даних.')


class EditCredentialEntity(CredentialEntity):
    def __init__(self, window, i, data):
        super().__init__(window, 'Редагування користувача', 'Редагувати')
        self.id = i

        if data:
            self.site_entry.insert(0, data[0])
            self.login_entry.insert(0, data[1])
            self.password_entry.insert(0, data[2])

    def perform_db_operation(self, site, login, password):
        db_proxy.edit_record(site, login, password)
        messagebox.showinfo('Успіх', 'Користувач відредагований.')


def main():
    Root()


if __name__ == '__main__':
    main()
