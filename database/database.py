import os
from contextlib import closing

import psycopg2


DB_CONFIG = {
    "dbname": "vmi_sentinel",
    "user": "vmi_app",
    "password": os.environ.get("VMI_DB_PASSWORD"),
    "host": "127.0.0.1",
    "port": 5432,
}


def get_connection():
    """Create and return a PostgreSQL connection."""
    password = os.environ.get("VMI_DB_PASSWORD")

    if not password:
        raise RuntimeError(
            "VMI_DB_PASSWORD environment variable is missing."
        )

    config = DB_CONFIG.copy()
    config["password"] = password

    return psycopg2.connect(**config)


def get_vm_id(vm_name):
    """Return the database ID of a registered virtual machine."""
    with closing(get_connection()) as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT vm_id FROM virtual_machines WHERE vm_name = %s",
                (vm_name,),
            )
            result = cursor.fetchone()

            if result is None:
                raise ValueError(
                    f"Virtual machine '{vm_name}' is not registered."
                )

            return result[0]


def insert_event(event):
    """Insert a processed monitoring event into PostgreSQL."""
    with closing(get_connection()) as conn:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO events (
                        event_id,
                        vm_id,
                        event_type,
                        event_timestamp,
                        process_id,
                        parent_process_id,
                        process_name,
                        memory_address,
                        memory_size,
                        description
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (event_id) DO NOTHING
                    """,
                    (
                        event["event_id"],
                        get_vm_id(event["vm_name"]),
                        event["event_type"],
                        event["timestamp"],
                        event.get("process_id"),
                        event.get("parent_process_id"),
                        event.get("process_name"),
                        event.get("memory_address"),
                        event.get("memory_size"),
                        event.get("description"),
                    ),
                )

                return cursor.rowcount == 1