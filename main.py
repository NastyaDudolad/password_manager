import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import hashlib
from pswd_mngr_db_proxy import *

db_proxy = DatabaseProxy(messagebox, MAIN_TABLE)


class Root:
    def __init__(self):
        self.credentials_entity = None

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
        entry_password = self.entry.get()  # Отримуємо введений пароль

        # Порівнюємо хеші введеного пароля та збереженого
        # if hashlib.md5(entry_password.encode('utf-8')).digest() == PASSWORD_HASH:
        #     open_credentials_window()  # Відкриваємо друге вікно
        # else:
        #     messagebox.showerror('Помилка', 'Неправильний пароль')

        # Відкриваємо друге вікно
        if not self.credentials_entity:
            self.credentials_entity = Credentials(self.root)
        else:
            if not self.credentials_entity.credentials_window_visibility:
                self.credentials_entity.show_credentials_window()


class Credentials:
    def __init__(self, root):
        self.id = 0
        self.data = []
        self.credentials_window_visibility = False

        self.window = tk.Toplevel(root)
        self.credentials_window_visibility = True
        self.window.title("Логіни та паролі")
        self.window.configure(bg=COLOR1)

        # Створіть Frame для Treeview і Scrollbar
        frame = tk.Frame(self.window)
        frame.pack(padx=10, pady=10, fill="both", expand=True)

        self.tree = ttk.Treeview(frame, columns=("site", 'login', 'password'), show="headings", height=5)
        self.tree.heading("site", text="Сайт")
        self.tree.heading("login", text="Логін")
        self.tree.heading("password", text="Пароль")

        # Create a Scrollbar
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        self.update_treeview()

        # Відображення Treeview
        self.tree.pack(padx=10, pady=10)

        def on_select(event):
            # Get the selected item
            selected_item = self.tree.selection()
            index = None

            # Check if an item is selected
            if selected_item:
                # Get the index of the selected item
                index = self.tree.index(selected_item[0])
                print("Index of selected row:", index)
            self.id = self.data[index][0]

        self.tree.bind('<<TreeviewSelect>>', on_select)

        button_frame = tk.Frame(self.window, bg=COLOR1)
        button_frame.pack(pady=10)

        # Кнопки
        close_button = tk.Button(button_frame, text="Закрити", command=self.close_credentials_window, width=15)
        close_button.grid(row=0, column=0, padx=5)

        add_button = tk.Button(button_frame, text='Додати запис', command=lambda: AddCredentialEntity(self), width=15)
        add_button.grid(row=0, column=1, padx=5)

        edit_button = tk.Button(button_frame, text='Редагувати', command=lambda: EditCredentialEntity(self), width=15)
        edit_button.grid(row=0, column=2, padx=5)

        delete_button = tk.Button(button_frame, text='Видалити', command=lambda: DeleteCredentialEntity(self), width=15)
        delete_button.grid(row=0, column=3, padx=5)

    def show_credentials_window(self):
        self.window.deiconify()
        self.credentials_window_visibility = True

    def close_credentials_window(self):
        self.window.withdraw()
        self.credentials_window_visibility = False

    def update_treeview(self):
        # Очищаємо всі існуючі записи в Treeview
        self.tree.delete(*self.tree.get_children())

        # Отримуємо нові дані
        self.data = db_proxy.get_records()

        # Додаємо нові записи в Treeview
        for j, cred in enumerate(self.data):
            self.tree.insert("", "end", values=(cred[1], cred[2], cred[3]))


class CredentialEntity:
    def __init__(self, window, title, btn_title):
        self.top_window = window
        self.title = title
        self.btn_title = btn_title

        # Створити вікно
        self.window = tk.Toplevel(self.top_window)
        self.window.title(self.title)
        self.window.geometry("300x250")

        # Поля для введення нових даних
        tk.Label(self.window, text="Сайт:").pack(pady=5)
        self.site_entry = tk.Entry(self.window)
        self.site_entry.pack(pady=5)

        tk.Label(self.window, text="Логін:").pack(pady=5)
        self.login_entry = tk.Entry(self.window)
        self.login_entry.pack(pady=5)

        tk.Label(self.window, text="Пароль:").pack(pady=5)
        self.password_entry = tk.Entry(self.window)
        self.password_entry.pack(pady=5)

        tk.Button(self.window, text=self.btn_title, command=self.process_data).pack(pady=10)

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
    def __init__(self, creds):
        super().__init__(creds.window, 'Додавання користувача', 'Додати')
        self.creds = creds

    def perform_db_operation(self, site, login, password):
        db_proxy.add_record(site, login, password)
        messagebox.showinfo('Успіх', 'Користувач доданий до бази даних.')
        self.creds.update_treeview()
        self.window.destroy()


class EditCredentialEntity(CredentialEntity):
    def __init__(self, creds):
        self.creds = creds
        self.id = creds.id
        super().__init__(creds.window, f'Редагування запису {self.id}', 'Редагувати')

        data = db_proxy.get_record(self.id)

        if data:
            self.site_entry.insert(0, data[0][1])
            self.login_entry.insert(0, data[0][2])
            self.password_entry.insert(0, data[0][3])

    def perform_db_operation(self, site, login, password):
        db_proxy.edit_record(self.id, site, login, password)
        messagebox.showinfo('Успіх', 'Користувач відредагований.')
        self.creds.update_treeview()
        self.window.destroy()


class DeleteCredentialEntity:
    def __init__(self, creds):
        self.creds = creds
        if messagebox.askyesno('delete', 'Ви впевнені що хочете видалити запис?'):
            db_proxy.delete_record(creds.id)
            messagebox.showinfo('Успіх', 'Запис видалено.')
            creds.update_treeview()


def main():
    Root()


if __name__ == '__main__':
    main()
