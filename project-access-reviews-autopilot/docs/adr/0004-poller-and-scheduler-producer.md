# Production Producer is Graph poller plus scheduler

Lab Producer emits Review Events from fixtures/simulator. Production Producer is a Graph poller that discovers Pending Decision Items, plus a scheduler that derives Overdue and ReminderDue from due dates. We stay on Access Reviews—not Access Package events—and do not commit to Microsoft Graph → Event Grid partner delivery unless that resource is actually supported.
