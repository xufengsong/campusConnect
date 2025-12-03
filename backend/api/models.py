
# api/models.py

from django.db import models
from django.db.models import F
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import timedelta
from pgvector.django import VectorField
import uuid


class SubscriptionTier(models.Model):
    """
    Model to define subscription tiers and their limits
    """
    TIER_CHOICES = [
        ('free', 'Free'),
        ('basic', 'Basic'),
        ('premium', 'Premium'),
    ]
    
    name = models.CharField(max_length=20, choices=TIER_CHOICES, unique=True)
    display_name = models.CharField(max_length=50)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    monthly_translation_limit = models.IntegerField()
    daily_translation_limit = models.IntegerField()
    features = models.JSONField(default=list)  # List of features for this tier
    
    def __str__(self):
        return self.display_name

class User(AbstractUser):
    """
    Extends Django's built-in User model to add relationships for
    known and learning words and subscription information.
    """
    name = models.CharField(max_length=255, blank=True)
    university = models.CharField(max_length=255, blank=True)
    country = models.CharField(max_length=255, blank=True)
    avatar = models.CharField(max_length=500, blank=True, default="/placeholder.svg")

    email = models.EmailField(unique=True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    # Subscription fields
    subscription_tier = models.ForeignKey(
        SubscriptionTier, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        default=None
    )

    subscription_start_date = models.DateTimeField(null=True, blank=True)
    subscription_end_date = models.DateTimeField(null=True, blank=True)
    is_subscription_active = models.BooleanField(default=False)
    
    # Usage tracking
    monthly_translations_used = models.IntegerField(default=0)
    daily_translations_used = models.IntegerField(default=0)
    last_translation_date = models.DateField(null=True, blank=True)
    last_monthly_reset = models.DateField(null=True, blank=True)


    def reset_usage_counters_if_needed(self):
        """
        Atomically checks and resets usage counters if a new day or month has begun.
        This should be called before checking limits.
        """
        today = timezone.now().date()
        
        # Reset daily counter if it's a new day
        if self.last_translation_date != today:
            self.daily_translations_used = 0
            self.last_translation_date = today

        # Reset monthly counter if it's a new month
        if not self.last_monthly_reset or self.last_monthly_reset.month != today.month:
            self.monthly_translations_used = 0
            self.last_monthly_reset = today
        
        # Note: We don't call self.save() here. 
        # The save will happen when usage is incremented.

    
    def get_current_tier(self):
        """Get the current subscription tier or return free tier"""
        if self.subscription_tier and self.is_subscription_active:
            return self.subscription_tier
        else:
            # Return free tier
            free_tier, created = SubscriptionTier.objects.get_or_create(
                name='free',
                defaults={
                    'display_name': 'Free',
                    'price': 0,
                    'monthly_translation_limit': 150,
                    'daily_translation_limit': 5,
                    'features': ['Basic translation', 'Limited vocabulary tracking']
                }
            )
            return free_tier
    

    def can_translate(self):
        """Check if user can perform translation based on their tier limits"""
        self.reset_usage_counters_if_needed()  # Update internal state but don't save yet

        tier = self.get_current_tier()
        
        # Check limits
        if self.daily_translations_used >= tier.daily_translation_limit:
            return False, "Daily analysis limit reached. Please upgrade or wait until tomorrow."
        
        if self.monthly_translations_used >= tier.monthly_translation_limit:
            return False, "Monthly analysis limit reached. Please upgrade or wait until next month."
        
        return True, "OK"

    
    def increment_translation_usage(self):
        """
        Atomically increments translation usage counters using F() expressions
        to prevent race conditions.
        """
        # Ensure counters are correctly set for today before incrementing
        self.reset_usage_counters_if_needed() 
        
        # Atomically increment the counters in the database
        self.daily_translations_used = F('daily_translations_used') + 1
        self.monthly_translations_used = F('monthly_translations_used') + 1
        
        # Save all changes at once (reset dates and incremented counters)
        self.save(update_fields=[
            'daily_translations_used', 
            'monthly_translations_used', 
            'last_translation_date',
            'last_monthly_reset'
        ])


class PaymentTransaction(models.Model):
    """
    Model to store PayPal payment transactions
    """
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
        ('refunded', 'Refunded'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    subscription_tier = models.ForeignKey(SubscriptionTier, on_delete=models.CASCADE)
    
    # PayPal specific fields
    paypal_order_id = models.CharField(max_length=255, unique=True)
    paypal_capture_id = models.CharField(max_length=255, blank=True, null=True)
    paypal_payer_id = models.CharField(max_length=255, blank=True, null=True)
    
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=3, default='USD')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Payment verification
    is_verified = models.BooleanField(default=False)
    verification_date = models.DateTimeField(null=True, blank=True)
    
    def __str__(self):
        return f"Payment {self.paypal_order_id} - {self.user.email} - {self.amount} {self.currency}"
    

class Project(models.Model):
    """
    Model to store data for each Project
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    project_name = models.CharField(max_length=255, blank=True)
    cognee_nodeset_name = models.CharField(max_length=255, blank=True)
    project_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True, blank=True)


    created_at = models.DateTimeField(auto_now_add=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True)


    
class ChatMemory(models.Model):
    """
    Model to store chat data for each Project
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE)


class Timetable(models.Model):
    """
    Model to store user course schedules.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='timetable_entries')
    course_name = models.CharField(max_length=255)
    professor_name = models.CharField(max_length=255, blank=True, null=True)
    location = models.CharField(max_length=255, blank=True, null=True)
    day_of_week = models.IntegerField(help_text="0=Monday, 1=Tuesday, etc.")
    start_time = models.IntegerField(help_text="Hour of the day (e.g., 9 for 9:00 AM)")
    duration = models.FloatField(help_text="Duration in hours")
    color = models.CharField(max_length=7, default="#8B7EF2", help_text="Hex color code")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.course_name} ({self.user.username})"


class ThreadPost(models.Model):
    """
    Model to store community feed posts.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='posts')
    content = models.TextField()
    image = models.CharField(max_length=500, blank=True, null=True)
    tags = models.JSONField(default=list, blank=True)
    likes_count = models.IntegerField(default=0)
    comments_count = models.IntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Post by {self.user.username} at {self.created_at}"