# core/consumers.py
from channels.generic.websocket import AsyncWebsocketConsumer
import json

class LogConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()

    async def receive(self, text_data):
        await self.send(text_data=json.dumps({'message': 'New log received'}))
