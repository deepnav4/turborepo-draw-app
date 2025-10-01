import { WebSocketServer } from 'ws';
import jwt, { JwtPayload } from "jsonwebtoken";
import { JWT_SECRET } from '@repo/backend-common/config';
import type { WebSocket as WsWebSocket } from 'ws';
import { prismaClient } from '@repo/db/client';

const wss = new WebSocketServer({ port: 8080 });


interface User{
  ws : WsWebSocket,
  rooms : string[],
  userId : string 
}

const users : User[] = [];

function checkUserNdecode(token: string): string | null{
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
  
    if (typeof decoded == "string") {
      return null;
    }
  
    if (!decoded || !decoded.userId) {
      return null;
    }
    return decoded.userId;
  } 
  catch (error) {
    return null;
  }
}

wss.on('connection', function connection(ws, request) {
  const url = request.url;
  if (!url) {
    return;
  }
  const queryParams = new URLSearchParams(url.split('?')[1]);
  const token = queryParams.get('token') || "";
  const userId = checkUserNdecode(token);
  if (!userId) {
    ws.close();
    return;
  }

  users.push({
    ws,
    rooms: [],
    userId
  });



  ws.on('message', async function message(data) {
    const parsedData = JSON.parse(data.toString());
    if(parsedData.type === "join_room"){
      const user = users.find(x => x.ws === ws);
      user?.rooms.push(parsedData.roomId);
    }
    if(parsedData.type === "leave_room"){
      const user = users.find(x => x.ws === ws);
      if(!user) return;
      user.rooms = user.rooms.filter(x => x !== parsedData.roomId);
    }
    if(parsedData.type === "chat"){
      const roomId = parsedData.roomId;
      const message = parsedData.message;

      await prismaClient.chat.create({
        data:{
          roomId,
          userId,
          message
        }
      });

      users.forEach(user => {
        if(user.rooms.includes(roomId)){
          user.ws.send(JSON.stringify({
            type: "chat",
            message,
          }));
        }
      })
    }
  });

});
