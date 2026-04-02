import django.db.models.deletion
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="ScanResult",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("url", models.URLField(max_length=2000)),
                ("status", models.CharField(
                    choices=[
                        ("pending", "Pending"),
                        ("running", "Running"),
                        ("done", "Done"),
                        ("failed", "Failed"),
                    ],
                    default="pending",
                    max_length=10,
                )),
                ("vibe_score", models.IntegerField(blank=True, null=True)),
                ("findings", models.JSONField(default=list)),
                ("progress", models.JSONField(default=list)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("error_message", models.TextField(blank=True, default="")),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
    ]
