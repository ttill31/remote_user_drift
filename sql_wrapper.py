import sqlite3
from typing import Any
from os.path import exists
from entra_user import EntraUser

class SQLWrapper:
    def __init__(self, db_name: str) -> None:
        self._connection: sqlite3.Connection | None = None

        if db_name:
            db_exists: bool = exists(db_name)

            try:
                self._connection = sqlite3.connect(db_name)
                self._connection.row_factory = sqlite3.Row

                if not db_exists and not self._populate_db():
                    print('Error creating database file.')
            except sqlite3.Error as err:
                print(f'Error: {err}')

    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._connection:
            self._connection.close()

        if exc_type:
            print(f'Exception: {exc_type}, {exc_val}')

    def _populate_db(self) -> bool:
        cur: sqlite3.Cursor | None = None
        success: bool = True


        try:
            if self._connection:
                cur = self._connection.execute('''CREATE TABLE employee_data(
                                        emp_object TEXT PRIMARY KEY,
                                        state TEXT NOT NULL
                                        )''')
                self._connection.commit()
        except sqlite3.Error as err:
            print(f'Error: {err}')
            success = False
        finally:
            if cur : cur.close()
            return success
    
    def create_employee_entry(self, emp_object_id: str, emp_state: str) -> bool:
        success: bool = True
        cur: sqlite3.Cursor | None = None

        try:
            if self._connection:
                sql_statement: str = '''
                                INSERT INTO employee_data
                                (emp_object, state)
                                VALUES
                                (?, ?);
                                '''

                cur = self._connection.cursor()
                cur.execute(sql_statement, (emp_object_id, emp_state))
                self._connection.commit()
        except sqlite3.Error as err:
            print(f'Error: {err}')
            success = False
        finally:
            if cur: cur.close()
            return success

    def update_employee_entry(self, emp_info: EntraUser) -> bool:
        success: bool = True
        cur: sqlite3.Cursor | None = None

        try:
            if self._connection:
                sql_statement: str = '''UPDATE employee_data
                                        SET state = ?
                                        WHERE emp_object = ?'''
                cur = self._connection.cursor()
                cur.execute(sql_statement, (emp_info.states.pop(), emp_info.id)) # If we have multiple states go ahead and pop whatever the first one on the set is
                self._connection.commit()
        except sqlite3.Error as err:
            print(f'Error: {err}')
            success = False
        finally:
            if cur: cur.close()
            return success

    def get_all_employee_entries(self) -> dict[str, str]:
        entries: dict[str, str] = dict()
        cur: sqlite3.Cursor | None = None
        
        try:
            if self._connection:
                cur = self._connection.execute('SELECT emp_object, state FROM employee_data')
                entries = {entry['emp_object']: entry['state'] for entry in cur.fetchall()}
        except sqlite3.Error as err:
            print(f'Error: {err}')
        finally:
            if cur: cur.close()
            return entries
        
    def get_specific_employee(self, emp_object: str) -> dict[str, str]:
        emp: dict[str, str] = dict()
        cur: sqlite3.Cursor | None = None

        try:
            if self._connection:
                sql_query: str = '''
                                SELECT emp_object, state
                                FROM employee_data
                                WHERE emp_object = ?
                                LIMIT 1
                                '''
                cur = self._connection.cursor()
                cur.execute(sql_query, (emp_object,))
                row: Any = cur.fetchone()
                emp = {
                    'emp_object': row['emp_object'],
                    'state': row['state']
                }
        except sqlite3.Error as err:
            print(f'Error {err}')
        finally:
            if cur: cur.close()
            return emp