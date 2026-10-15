from collector.event_model import VMEvent


class EventProcessor:

    def process(self, event: VMEvent) -> dict:
        """
        Convert a VMEvent into a standardized dictionary
        for database storage.
        """

        return {
            "event_id": event.event_id,
            "vm_name": event.vm_name,
            "event_type": event.event_type,
            "timestamp": event.timestamp.isoformat(),

            "process_id": event.process_id,
            "parent_process_id": event.parent_process_id,
            "process_name": event.process_name,

            "memory_address": event.memory_address,
            "memory_size": event.memory_size,

            "description": event.description
        }