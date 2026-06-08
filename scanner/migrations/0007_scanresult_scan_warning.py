from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scanner", "0006_three_tier_scores"),
    ]

    operations = [
        migrations.AddField(
            model_name="scanresult",
            name="scan_warning",
            field=models.TextField(blank=True, default=""),
        ),
    ]
