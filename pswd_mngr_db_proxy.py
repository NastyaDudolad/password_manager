# TODO: назву бази та таблиці треба винести в конфігураційний файл
import sqlite3
from config import *


class DatabaseProxy:
    def __init__(self, messagebox, table):
        self.connection = sqlite3.connect(DATABASE)
        self.cursor = self.connection.cursor()
        self.messagebox = messagebox
        self.table = table

    def get_records(self):
        self.cursor.execute(f'SELECT * FROM {self.table}')
        data = self.cursor.fetchall()

        return data

    def get_record(self, id):
        self.cursor.execute(f'SELECT * FROM {self.table} WHERE id = {id}')
        data = self.cursor.fetchall()

        return data

    def edit_record(self, id, site, login, password):
        if site and login and password:
            try:
                record_to_update = (site, login, password, id)
                self.cursor.execute(
                    f'UPDATE {self.table} SET site=?, login=?, password=? WHERE id=?',
                    record_to_update
                )
                self.connection.commit()

                self.messagebox.showinfo('Успіх', 'Інформація оновлена.')
            except ValueError:
                self.messagebox.showerror('Помилка', 'Будь ласка, введіть правильне значення')
        else:
            self.messagebox.showwarning('Попередження', 'Будь ласка, заповніть всі поля.')

    def add_record(self, site, login, password):
        self.cursor.execute(f'INSERT INTO {self.table} (site, login, password) VALUES (?, ?, ?)',
                            (site, login, password))
        self.connection.commit()

    def delete_record(self, id):
        self.cursor.execute(f'DELETE FROM {self.table} WHERE id=' + str(id))
        self.connection.commit()
