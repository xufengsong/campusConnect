from celery import shared_task
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from .models import User
from .utils import get_s3_audio_url
from pgvector.django import L2Distance
import numpy as np
import math

@shared_task
def get_vocab_random(user_id):  # user id here means one of the names of group
    """
    Randomly recommend 10 vocabs
    """
    
    vocab_items = Vocabulary.objects.order_by('?').all()[:10]

    # Serialize the queryset
    serializer = VocabularySerializer(vocab_items, many=True)
    data = serializer.data
    
    # Enhance the serialized data with full S3 URLs
    for item in data:
        if item.get('word_audio'):
            item['word_audio'] = get_s3_audio_url(item['word_audio'])
        
        if item.get('sentence_audio'):
            item['sentence_audio'] = get_s3_audio_url(item['sentence_audio'])

    # Get the channel layer
    channel_layer = get_channel_layer()

    # The group name must match the one in the consumer
    group_name = f'user_{user_id}'

    # Send a message to the user's group
    # We use async_to_sync to call the async channel layer method from sync Celery
    async_to_sync(channel_layer.group_send)(
        group_name,
        {
            "type": "task_result",  # This matches the method name in the consumer
            "data": data,
        }
    )

    return "Result sent"


@shared_task
def recommend_vocab(user_id):
    """
    Get 10 most close vocab embedding based on current user embedding 
    """

    user = User.objects.get(user_id=user_id)

    vocab_items = Vocabulary.objects.order_by(
        L2Distance('embedding', user.embedding)
    )[:5]

    # Serialize the queryset
    serializer = VocabularySerializer(vocab_items, many=True)
    data = serializer.data
    
    # Enhance the serialized data with full S3 URLs
    for item in data:
        if item.get('word_audio'):
            item['word_audio'] = get_s3_audio_url(item['word_audio'])
        
        if item.get('sentence_audio'):
            item['sentence_audio'] = get_s3_audio_url(item['sentence_audio'])

    # Get the channel layer
    channel_layer = get_channel_layer()

    # The group name must match the one in the consumer
    group_name = f'user_{user_id}'

    # Send a message to the user's group
    # We use async_to_sync to call the async channel layer method from sync Celery
    async_to_sync(channel_layer.group_send)(
        group_name,
        {
            "type": "task_result",  # This matches the method name in the consumer
            "data": data,
        }
    )

    return "Recommended Result sent"

@shared_task
def chatResponse(user_id):
    """
    Chat response of User message
    """

    user = User.objects.get(user_id = user_id)
    
    channel_layer = get_channel_layer()

    group_name = f'user_{user_id}'

    async_to_sync(channel_layer.group_send)(
        group_name,
        {
            "type": "chat_message",
            "data": data,
        }
    )

