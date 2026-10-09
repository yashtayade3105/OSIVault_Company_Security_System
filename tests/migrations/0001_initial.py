from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True
    dependencies = [
        ("audit", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="ConcreteAuditLog",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("timestamp", models.DateTimeField(db_index=True)),
                ("actor", models.CharField(max_length=255)),
                ("tenant", models.CharField(max_length=255)),
                ("resource_type", models.CharField(max_length=255)),
                ("resource_id", models.CharField(max_length=255)),
                ("action", models.CharField(max_length=255)),
                ("old_values", models.JSONField(blank=True, default=dict)),
                ("new_values", models.JSONField(blank=True, default=dict)),
                ("previous_hash", models.CharField(blank=True, max_length=128)),
                ("entry_hash", models.CharField(max_length=128)),
                ("envelope", models.JSONField()),
            ],
            options={
                "db_table": "test_concrete_audit_log",
            },
        ),
        migrations.CreateModel(
            name="PatientRecord",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("patient_name", models.CharField(max_length=255)),
                ("ssn", models.TextField(blank=True, null=True)),
                ("ssn_search", models.CharField(blank=True, db_index=True, max_length=64, null=True)),
                ("secret_code", models.TextField(blank=True, null=True)),
                ("medical_history", models.TextField(blank=True, null=True)),
            ],
            options={
                "db_table": "test_patient_record",
            },
        ),
    ]
