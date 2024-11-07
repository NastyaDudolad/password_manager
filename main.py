import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import hashlib
from pswd_mngr_db_proxy import *

# TODO: if __main__
# refactor in oop style
# розглянути повторне відкриття

db_proxy = DatabaseProxy(messagebox, MAIN_TABLE)
credentials_window_visibility = False


# Функція для перевірки пароля
def check_password():
    global credentials_window_visibility
    if not credentials_window_visibility:
        credentials_window_visibility = True
        entry_password = entry.get()  # Отримуємо введений пароль

        # Порівнюємо хеші введеного пароля та збереженого
        # if hashlib.md5(entry_password.encode('utf-8')).digest() == PASSWORD_HASH:
        #     open_credentials_window()  # Відкриваємо друге вікно
        # else:
        #     messagebox.showerror('Помилка', 'Неправильний пароль')
        open_credentials_window()  # Відкриваємо друге вікно


# Функція для відкриття другого вікна з логінами та паролями
def open_credentials_window():
    credentials_window = tk.Toplevel(root)
    credentials_window.title("Логіни та паролі")
    # credentials_window.geometry("300x200")
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

    # Кнопка для закриття другого вікна
    tk.Button(credentials_window, text="Закрити", command=credentials_window.destroy).pack(pady=10)
    add_button = tk.Button(credentials_window,
                           text='Додати запис', pady=10, command=lambda w=credentials_window: open_add_window(w))
    add_button.pack()
    edit_button = tk.Button(credentials_window,
                            text='Редагувати запис', pady=10, command=lambda w=credentials_window: open_edit_window(w))
    edit_button.pack()


def add_edit_win(window):
    # Поля для введення нових даних
    tk.Label(window, text="Сайт:").pack(pady=5)
    site_entry = tk.Entry(window)
    site_entry.pack(pady=5)

    tk.Label(window, text="Логін:").pack(pady=5)
    login_entry = tk.Entry(window)
    login_entry.pack(pady=5)

    tk.Label(window, text="Пароль:").pack(pady=5)
    password_entry = tk.Entry(window)
    password_entry.pack(pady=5)

    tk.Button(window,
              text="Додати",
              command=lambda s=site_entry, l=login_entry, p=password_entry: save_new_record(s, l, p)).pack(pady=10)


# 3 окно
def open_add_window(window):
    add_window = tk.Toplevel(window)
    add_window.title('Додавання користувача')
    add_window.geometry("300x250")
    add_edit_win(add_window)


# окно редактирования
def open_edit_window(window):
    edit_window = tk.Toplevel(window)
    edit_window.title('Редагування користувача')
    edit_window.geometry("300x250")
    add_edit_win(edit_window)


# Функція для збереження нового користувача у базу
def save_new_record(site_entry, login_entry, password_entry):
    site = site_entry.get()
    login = login_entry.get()
    password = password_entry.get()

    if site and login and password:
        try:
            db_proxy.add_record(site, login, password)
        except ValueError:
            messagebox.showerror('Помилка', 'Будь ласка, введіть правильне значення')
    else:
        messagebox.showwarning('Попередження', 'Будь ласка, заповніть всі поля.')


root = tk.Tk()
root.title("Менеджер паролів")
root.geometry("400x300")  # Розмір вікна

# Створюємо фрейм для розташування елементів у центрі
frame = tk.Frame(root, bg=COLOR1, padx=20, pady=20)
frame.place(relx=0.5, rely=0.5, anchor="center")  # Центруємо фрейм

# Лейбл для вводу пароля
label = tk.Label(frame, text="Введіть пароль:", bg=COLOR1)
label.pack(pady=10)

# Поле для вводу пароля
entry = tk.Entry(frame, width=30, show='*')
entry.pack(pady=10)

# Кнопка для перевірки пароля
button = tk.Button(frame, text="Увійти", command=check_password)
button.pack(pady=10)

root.mainloop()


