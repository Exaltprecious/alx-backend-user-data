#!/usr/bin/env python3
"""A module for filtering logs. 
"""
import os
import re
import logging
import mysql.connector
from typing import List


# Patterns for redacting
patterns = {
    'extract': lambda fields, separator: r'(?P<field>{})=[^{}]*'.format('|'.join(fields), separator),
    'replace': lambda redaction: r'\g<field>={}'.format(redaction),
}

PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(fields: List[str], redaction: str, message: str, separator: str) -> str:
    """Filters a log line.
    Args:
        fields (List[str]): The list of fields to redact
        redaction (str): The string to replace the sensitive data with
        message (str): The message to filter
        separator (str): The separator between the log fields
    Returns:
        str: The redacted log line
    """
    extract, replace = patterns["extract"], patterns["replace"]
    return re.sub(extract(fields, separator), replace(redaction), message)


def get_logger() -> logging.Logger:
    """Creates a new logger for user data. 
    Returns:
        logging.Logger: The logger instance
    """
    logger = logging.getLogger("user_data")
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(stream_handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """Creates a connector to a database.
    Returns:
        mysql.connector.connection.MySQLConnection: The database connection
    """
    db_host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = os.getenv("PERSONAL_DATA_DB_NAME", "")
    db_user = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    db_pwd = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    connection = mysql.connector.connect(
        host=db_host,
        port=3306,
        user=db_user,
        password=db_pwd,
        database=db_name,
    )
    return connection


def main():
    """Logs the information about user records in a table.
    """
    fields = "name,email,phone,ssn,password,ip,last_login,user_agent"
    columns = fields.split(',')
    query = "SELECT {} FROM users;".format(fields)
    
    # Initialize logger
    info_logger = get_logger()
    
    # Database connection
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute(query)
            rows = cursor.fetchall()
            
            # Iterate over rows and log each record
            for row in rows:
                record = [f"{column}={value}" for column, value in zip(columns, row)]
                msg = '{};'.format('; '.join(record))
                
                # Log the message
                info_logger.info(msg)
    except mysql.connector.Error as e:
        info_logger.error(f"Error connecting to the database: {e}")
    finally:
        if connection.is_connected():
            connection.close()


class RedactingFormatter(logging.Formatter):
    """Redacting Formatter class for filtering PII data
    """
    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    FORMAT_FIELDS = ('name', 'levelname', 'asctime', 'message')
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super().__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Formats a LogRecord.
        Args:
            record (logging.LogRecord): The log record to format
        Returns:
            str: The formatted and redacted message
        """
        msg = super().format(record)
        # Apply redaction on the message
        txt = filter_datum(self.fields, self.REDACTION, msg, self.SEPARATOR)
        return txt


if __name__ == "__main__":
    main()
