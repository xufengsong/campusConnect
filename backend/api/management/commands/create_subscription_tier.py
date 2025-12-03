# management/commands/create_subscription_tiers.py
# Create this file in your_app/management/commands/

from django.core.management.base import BaseCommand
from api.models import SubscriptionTier

class Command(BaseCommand):
    help = 'Creates default subscription tiers'

    def handle(self, *args, **options):
        # Create Free tier
        free_tier, created = SubscriptionTier.objects.get_or_create(
            name='free',
            defaults={
                'display_name': 'Free',
                'price': 0.00,
                'monthly_translation_limit': 50,
                'daily_translation_limit': 5,
                'features': [
                    'Basic translation',
                    'Limited vocabulary tracking',
                    'Community support'
                ]
            }
        )
        if created:
            self.stdout.write(self.style.SUCCESS('Created Free tier'))
        else:
            self.stdout.write(self.style.WARNING('Free tier already exists'))

        # Create Basic tier
        basic_tier, created = SubscriptionTier.objects.get_or_create(
            name='basic',
            defaults={
                'display_name': 'Basic',
                'price': 9.99,
                'monthly_translation_limit': 500,
                'daily_translation_limit': 50,
                'features': [
                    'Advanced translation',
                    'Unlimited vocabulary tracking',
                    'Priority support',
                    'Export vocabulary lists',
                    'Learning analytics'
                ]
            }
        )
        if created:
            self.stdout.write(self.style.SUCCESS('Created Basic tier'))
        else:
            self.stdout.write(self.style.WARNING('Basic tier already exists'))

        # Create Premium tier
        premium_tier, created = SubscriptionTier.objects.get_or_create(
            name='premium',
            defaults={
                'display_name': 'Premium',
                'price': 19.99,
                'monthly_translation_limit': 2000,
                'daily_translation_limit': 200,
                'features': [
                    'Advanced translation with context',
                    'Unlimited vocabulary tracking',
                    'Priority support',
                    'Export vocabulary lists',
                    'Advanced learning analytics',
                    'Custom study schedules',
                    'Offline mode support',
                    'Multiple language pairs'
                ]
            }
        )
        if created:
            self.stdout.write(self.style.SUCCESS('Created Premium tier'))
        else:
            self.stdout.write(self.style.WARNING('Premium tier already exists'))

        self.stdout.write(self.style.SUCCESS('Subscription tiers setup complete!'))

# Run this command with: python manage.py create_subscription_tiers