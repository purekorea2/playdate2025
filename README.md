# playdate2025
Playdate App 2025

1. 회원가입 / 로그인 (JWT 인증)
2. 사용자 프로필 생성 / 수정
3. 친구 요청 보내기
4. 친구 요청 수락 / 거절
5. 친구 목록 보기
6. 사용자 친구 검색 기능
7. 채팅 기능 (기본 WebSocket 구조)
8. 실시간 온라인 상태 표시
9. 친구 매칭 알고리즘 취미 / 지역 / 나이


기능 1. 회원가입 및 로그인 (JWT 인증)
/backend/routes/auth.ts

import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import User from '../models/User';

const router = express.Router();

// 회원가입 API
router.post('/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    // 비밀번호 암호화
    const hashedPassword = await bcrypt.hash(password, 10);

    // 새로운 유저 생성
    const user = new User({ email, password: hashedPassword, name });
    await user.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

// 로그인 API
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User not found' });

    // 비밀번호 확인
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

    // JWT 생성
    const token = jwt.sign({ userId: user._id }, 'jwt_secret', { expiresIn: '1h' });

    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

export default router;
설명: bcrypt를 이용해 비밀번호를 암호화하고 JWT로 토큰을 발급해 로그인을 구현했어.

기능 2. 사용자 프로필 생성 및 수정
/backend/routes/profile.ts

import express from 'express';
import User from '../models/User';
import authMiddleware from '../middleware/auth';

const router = express.Router();

// 프로필 조회
router.get('/me', authMiddleware, async (req, res) => {
  const user = await User.findById(req.user.userId);
  res.json(user);
});

// 프로필 수정
router.put('/me', authMiddleware, async (req, res) => {
  const { name, age, location, hobbies } = req.body;

  const updatedUser = await User.findByIdAndUpdate(
    req.user.userId,
    { name, age, location, hobbies },
    { new: true }
  );

  res.json(updatedUser);
});

export default router;
설명: JWT 인증 미들웨어를 통해 로그인된 사용자의 정보를 수정할 수 있게 했어.

기능 3. 친구 요청 보내기
/backend/routes/friends.ts

import express from 'express';
import User from '../models/User';
import authMiddleware from '../middleware/auth';

const router = express.Router();

// 친구 요청 보내기
router.post('/request/:targetId', authMiddleware, async (req, res) => {
  const targetId = req.params.targetId;
  const senderId = req.user.userId;

  const targetUser = await User.findById(targetId);
  if (!targetUser) return res.status(404).json({ error: 'User not found' });

  // 요청 중복 확인
  if (targetUser.friendRequests.includes(senderId)) {
    return res.status(400).json({ error: 'Request already sent' });
  }

  targetUser.friendRequests.push(senderId);
  await targetUser.save();

  res.json({ message: 'Friend request sent' });
});

export default router;
설명: 로그인된 사용자가 다른 사용자에게 친구 요청을 보낼 수 있어. 중복 체크도 포함했지.

기능 4. 친구 요청 수락 및 거절
이 기능은 내가 받은 친구 요청을 수락하거나 거절할 수 있게 해주는 기능이야.

/backend/routes/friends.ts에 이어서 작성:

// 친구 요청 수락
router.post('/accept/:senderId', authMiddleware, async (req, res) => {
  const receiverId = req.user.userId;
  const senderId = req.params.senderId;

  const receiver = await User.findById(receiverId);
  const sender = await User.findById(senderId);

  if (!receiver || !sender) return res.status(404).json({ error: 'User not found' });

  // 요청이 존재하는지 확인
  if (!receiver.friendRequests.includes(senderId)) {
    return res.status(400).json({ error: 'No friend request found' });
  }

  // 친구로 추가
  receiver.friends.push(senderId);
  sender.friends.push(receiverId);

  // 요청 삭제
  receiver.friendRequests = receiver.friendRequests.filter(id => id.toString() !== senderId);
  await receiver.save();
  await sender.save();

  res.json({ message: 'Friend request accepted' });
});

// 친구 요청 거절
router.post('/reject/:senderId', authMiddleware, async (req, res) => {
  const receiverId = req.user.userId;
  const senderId = req.params.senderId;

  const receiver = await User.findById(receiverId);
  if (!receiver) return res.status(404).json({ error: 'User not found' });

  // 요청 삭제
  receiver.friendRequests = receiver.friendRequests.filter(id => id.toString() !== senderId);
  await receiver.save();

  res.json({ message: 'Friend request rejected' });
});
설명: accept API는 상대방과 서로의 friends 배열에 ID를 추가하고, reject는 요청만 삭제해. 두 명의 유저 정보를 모두 찾아야 해.

기능 5. 친구 목록 보기
이 기능은 나의 친구 리스트를 불러오는 기능이야.

// 친구 목록 보기
router.get('/list', authMiddleware, async (req, res) => {
  const userId = req.user.userId;

  const user = await User.findById(userId).populate('friends', 'name email');
  if (!user) return res.status(404).json({ error: 'User not found' });

  res.json(user.friends);
});
설명: MongoDB의 populate를 써서 친구들의 이름, 이메일을 가져오고 있어. friends 배열에는 ObjectId들이 들어 있어서, 실제 유저 정보로 변환해주는 거야.

기능 6. 사용자 검색 기능 (이름 기반)
이건 이름으로 다른 사람을 찾을 수 있게 해주는 기능이야.

// 사용자 검색
router.get('/search', authMiddleware, async (req, res) => {
  const { name } = req.query;

  // 정규식으로 유사한 이름 찾기 (대소문자 무시)
  const users = await User.find({
    name: { $regex: name, $options: 'i' }
  }).select('name email');

  res.json(users);
});
설명: ?name=Alex 이런 식으로 쿼리를 보내면 regex를 통해 비슷한 이름을 가진 사람들을 찾아줘. i 옵션은 대소문자를 구분하지 않게 해줘.

기능 7. 채팅 기능 (기본 WebSocket 구조)
우선 WebSocket 서버는 클라이언트와 실시간 통신을 가능하게 해줘. 여기선 socket.io를 사용해서 사용자 간의 메시지를 주고받을 수 있게 만들 거야.

server.ts (백엔드 서버 시작 파일)

import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import mongoose from 'mongoose';
import cors from 'cors';
import authRoutes from './routes/auth';
import profileRoutes from './routes/profile';
import friendRoutes from './routes/friends';
import { setupChatHandlers } from './socket/chatHandlers';

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*' }
});

// DB 연결
mongoose.connect('mongodb://localhost:27017/friends-app');

// 미들웨어
app.use(cors());
app.use(express.json());

// 라우터
app.use('/api/auth', authRoutes);
app.use('/api/profile', profileRoutes);
app.use('/api/friends', friendRoutes);

// WebSocket 연결 처리
io.on('connection', (socket) => {
  console.log('New client connected:', socket.id);
  setupChatHandlers(socket, io); // 채팅 이벤트 핸들러 연결
});

server.listen(5000, () => {
  console.log('Server running on http://localhost:5000');
});

socket/chatHandlers.ts

import { Server, Socket } from 'socket.io';

interface MessagePayload {
  sender: string;
  receiver: string;
  content: string;
}

export const setupChatHandlers = (socket: Socket, io: Server) => {
  // 채팅 메시지 수신
  socket.on('send_message', (data: MessagePayload) => {
    const { sender, receiver, content } = data;

    // 특정 사용자에게 메시지 보내기
    io.to(receiver).emit('receive_message', { sender, content });
  });

  // 특정 유저 ID로 방 설정
  socket.on('join', (userId: string) => {
    socket.join(userId);
    console.log(`User ${userId} joined their room.`);
  });
};
설명:

클라이언트가 join 이벤트로 자신의 ID 방에 들어오고,

메시지는 send_message로 상대 ID 방에 전달돼.
이 구조 덕분에 실시간 메시지를 주고받을 수 있어!

기능 8. 실시간 온라인 상태 표시
이 기능은 누가 온라인인지 표시해주는 기능이야.

let onlineUsers: { [userId: string]: string } = {};

export const setupChatHandlers = (socket: Socket, io: Server) => {
  // 유저 로그인 시
  socket.on('user_connected', (userId: string) => {
    onlineUsers[userId] = socket.id;
    io.emit('online_users', Object.keys(onlineUsers)); // 전체 유저에게 전송
  });

  // 유저 로그아웃 시
  socket.on('disconnect', () => {
    for (const userId in onlineUsers) {
      if (onlineUsers[userId] === socket.id) {
        delete onlineUsers[userId];
        break;
      }
    }
    io.emit('online_users', Object.keys(onlineUsers));
  });

  // 메시지 핸들링은 이전 그대로 유지
};
설명:
사용자가 로그인하면 user_connected 이벤트로 온라인 리스트에 추가되고,
연결이 끊기면 자동으로 제거돼. 프론트에서는 이걸 받아서 표시하면 돼.

기능 9. 상세한 사용자 매칭 알고리즘 (취미 + 지역 기반)
이건 핵심 기능! 비슷한 취미와 같은 지역 사람을 추천해주는 로직이야.

// 사용자 매칭 기능
router.get('/match', authMiddleware, async (req, res) => {
  const user = await User.findById(req.user.userId);

  if (!user) return res.status(404).json({ error: 'User not found' });

  const matches = await User.find({
    _id: { $ne: user._id }, // 자기 자신 제외
    location: user.location, // 지역이 같고
    hobbies: { $in: user.hobbies } // 취미가 겹치는 사람
  }).select('name email hobbies location');

  res.json(matches);
});
설명:

location이 같고,

hobbies 배열에서 겹치는 게 하나라도 있으면 매칭돼.

자기 자신은 제외하고 결과를 보여줘.

이제 백엔드에 이어서 프론트엔드 화면 구성 (React + Next.js + TypeScript) 도 시작하자.

오늘은 우선 기능 1~3:

회원가입

로그인

사용자 프로필 관리 (조회/수정)
이걸 기반으로 완전한 실제 페이지 구조, 컴포넌트 구조, API 요청 처리, 상태 관리까지 전부 아주 자세하게 보여줄게.

프로젝트 구조 추천 (Next.js App Router)

/app
  /register
  /login
  /profile
  /layout.tsx
  /page.tsx
/components
  /Navbar.tsx
  /ProtectedRoute.tsx
/lib
  /api.ts      <-- axios 인스턴스
  /auth.ts     <-- JWT 저장/삭제
/middleware.ts
/types.d.ts

1. 회원가입 페이지 - /app/register/page.tsx

'use client';

import { useState } from 'react';
import axios from '@/lib/api';
import { useRouter } from 'next/navigation';

export default function RegisterPage() {
  const router = useRouter();
  const [form, setForm] = useState({ name: '', email: '', password: '' });

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = async () => {
    try {
      await axios.post('/auth/register', form);
      alert('Registered successfully!');
      router.push('/login');
    } catch (err) {
      alert('Failed to register');
    }
  };

  return (
    <div>
      <h2>Sign Up</h2>
      <input name="name" onChange={handleChange} placeholder="Name" />
      <input name="email" onChange={handleChange} placeholder="Email" />
      <input name="password" type="password" onChange={handleChange} placeholder="Password" />
      <button onClick={handleSubmit}>Register</button>
    </div>
  );
}

2. 로그인 페이지 - /app/login/page.tsx

'use client';

import { useState } from 'react';
import axios from '@/lib/api';
import { useRouter } from 'next/navigation';
import { setToken } from '@/lib/auth';

export default function LoginPage() {
  const router = useRouter();
  const [form, setForm] = useState({ email: '', password: '' });

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = async () => {
    try {
      const res = await axios.post('/auth/login', form);
      setToken(res.data.token);
      alert('Logged in!');
      router.push('/profile');
    } catch (err) {
      alert('Login failed');
    }
  };

  return (
    <div>
      <h2>Login</h2>
      <input name="email" onChange={handleChange} placeholder="Email" />
      <input name="password" type="password" onChange={handleChange} placeholder="Password" />
      <button onClick={handleSubmit}>Login</button>
    </div>
  );
}

3. 프로필 페이지 - /app/profile/page.tsx

'use client';

import { useEffect, useState } from 'react';
import axios from '@/lib/api';
import { getToken } from '@/lib/auth';

export default function ProfilePage() {
  const [profile, setProfile] = useState({
    name: '', age: '', location: '', hobbies: ''
  });

  const loadProfile = async () => {
    const res = await axios.get('/profile/me', {
      headers: { Authorization: `Bearer ${getToken()}` }
    });
    setProfile(res.data);
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setProfile({ ...profile, [e.target.name]: e.target.value });
  };

  const updateProfile = async () => {
    await axios.put('/profile/me', profile, {
      headers: { Authorization: `Bearer ${getToken()}` }
    });
    alert('Profile updated!');
  };

  useEffect(() => {
    loadProfile();
  }, []);

  return (
    <div>
      <h2>My Profile</h2>
      <input name="name" value={profile.name} onChange={handleChange} />
      <input name="age" value={profile.age} onChange={handleChange} />
      <input name="location" value={profile.location} onChange={handleChange} />
      <input name="hobbies" value={profile.hobbies} onChange={handleChange} />
      <button onClick={updateProfile}>Update</button>
    </div>
  );
}

공통 유틸 코드
/lib/api.ts

import axios from 'axios';

const instance = axios.create({
  baseURL: 'http://localhost:5000/api',
});

export default instance;

/lib/auth.ts

export const setToken = (token: string) => {
  localStorage.setItem('token', token);
};

export const getToken = () => {
  return localStorage.getItem('token');
};

export const removeToken = () => {
  localStorage.removeItem('token');
};

오늘 구현할 프론트엔드 기능
친구 요청 보내기

친구 요청 수락 / 거절

친구 목록 보기

사용자 검색

기본 전제 (필수 상태 관리)

// types.d.ts
export interface User {
  _id: string;
  name: string;
  email: string;
  location?: string;
  hobbies?: string[];
}

export interface FriendRequest {
  _id: string;
  name: string;
  email: string;
}

1. 친구 검색 & 요청 보내기 – /app/search/page.tsx

'use client';

import { useState } from 'react';
import axios from '@/lib/api';
import { getToken } from '@/lib/auth';
import { User } from '@/types';

export default function SearchPage() {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<User[]>([]);

  const searchUsers = async () => {
    const res = await axios.get(`/friends/search?name=${query}`, {
      headers: { Authorization: `Bearer ${getToken()}` },
    });
    setResults(res.data);
  };

  const sendRequest = async (targetId: string) => {
    await axios.post(`/friends/request/${targetId}`, {}, {
      headers: { Authorization: `Bearer ${getToken()}` },
    });
    alert('Request sent!');
  };

  return (
    <div>
      <h2>Search Users</h2>
      <input value={query} onChange={(e) => setQuery(e.target.value)} />
      <button onClick={searchUsers}>Search</button>

      {results.map(user => (
        <div key={user._id}>
          <p>{user.name} ({user.email})</p>
          <button onClick={() => sendRequest(user._id)}>Add Friend</button>
        </div>
      ))}
    </div>
  );
}

2. 친구 요청 수락/거절 – /app/requests/page.tsx

'use client';

import { useEffect, useState } from 'react';
import axios from '@/lib/api';
import { getToken } from '@/lib/auth';
import { FriendRequest } from '@/types';

export default function RequestsPage() {
  const [requests, setRequests] = useState<FriendRequest[]>([]);

  const loadRequests = async () => {
    const res = await axios.get('/profile/me', {
      headers: { Authorization: `Bearer ${getToken()}` },
    });
    const user = res.data;
    setRequests(user.friendRequests || []);
  };

  const respondRequest = async (senderId: string, action: 'accept' | 'reject') => {
    await axios.post(`/friends/${action}/${senderId}`, {}, {
      headers: { Authorization: `Bearer ${getToken()}` },
    });
    loadRequests(); // refresh
  };

  useEffect(() => {
    loadRequests();
  }, []);

  return (
    <div>
      <h2>Friend Requests</h2>
      {requests.length === 0 && <p>No pending requests.</p>}
      {requests.map(req => (
        <div key={req._id}>
          <p>{req.name}</p>
          <button onClick={() => respondRequest(req._id, 'accept')}>Accept</button>
          <button onClick={() => respondRequest(req._id, 'reject')}>Reject</button>
        </div>
      ))}
    </div>
  );
}

3. 친구 리스트 보기 – /app/friends/page.tsx

'use client';

import { useEffect, useState } from 'react';
import axios from '@/lib/api';
import { getToken } from '@/lib/auth';
import { User } from '@/types';

export default function FriendsPage() {
  const [friends, setFriends] = useState<User[]>([]);

  const loadFriends = async () => {
    const res = await axios.get('/friends/list', {
      headers: { Authorization: `Bearer ${getToken()}` },
    });
    setFriends(res.data);
  };

  useEffect(() => {
    loadFriends();
  }, []);

  return (
    <div>
      <h2>My Friends</h2>
      {friends.map(friend => (
        <div key={friend._id}>
          <p>{friend.name} ({friend.email})</p>
        </div>
      ))}
    </div>
  );
}

이제 하이라이트인 실시간 채팅 기능과 온라인 상태 표시를 예쁘고 실용적인 UI와 함께 아주 자세하게 구현해볼게.

우리는 Socket.IO 클라이언트를 사용해서 실시간 통신을 처리하고, React 상태로 사용자들의 온라인 상태와 메시지를 관리할 거야.

1. 필요한 패키지 설치 (프론트엔드)

npm install socket.io-client

2. WebSocket 설정 – /lib/socket.ts

import { io } from 'socket.io-client';

const socket = io('http://localhost:5000', {
  autoConnect: false,
});

export default socket;
설명: autoConnect: false로 설정하고, 로그인 후 수동으로 연결해줘.

3. 공통 Socket 관리 Context – /contexts/SocketContext.tsx

'use client';

import { createContext, useContext, useEffect, useState } from 'react';
import socket from '@/lib/socket';
import { getToken } from '@/lib/auth';

const SocketContext = createContext<any>(null);

export const SocketProvider = ({ userId, children }: { userId: string, children: React.ReactNode }) => {
  const [onlineUsers, setOnlineUsers] = useState<string[]>([]);

  useEffect(() => {
    if (!userId) return;

    socket.connect();
    socket.emit('user_connected', userId);

    socket.on('online_users', (users: string[]) => {
      setOnlineUsers(users);
    });

    return () => {
      socket.disconnect();
    };
  }, [userId]);

  return (
    <SocketContext.Provider value={{ socket, onlineUsers }}>
      {children}
    </SocketContext.Provider>
  );
};

export const useSocket = () => useContext(SocketContext);
설명: 이 context를 사용하면 전체 앱에서 socket과 온라인 유저 상태를 쉽게 접근할 수 있어.

4. 채팅 UI 컴포넌트 – /app/chat/page.tsx

'use client';

import { useEffect, useState } from 'react';
import { useSocket } from '@/contexts/SocketContext';

interface Message {
  sender: string;
  content: string;
}

export default function ChatPage() {
  const { socket, onlineUsers } = useSocket();
  const [selectedUser, setSelectedUser] = useState<string | null>(null);
  const [message, setMessage] = useState('');
  const [messages, setMessages] = useState<Message[]>([]);

  useEffect(() => {
    if (!socket) return;

    socket.on('receive_message', (msg: Message) => {
      setMessages((prev) => [...prev, msg]);
    });

    return () => {
      socket.off('receive_message');
    };
  }, [socket]);

  const handleSend = () => {
    if (!selectedUser || !message) return;
    socket.emit('send_message', {
      sender: socket.id,
      receiver: selectedUser,
      content: message,
    });

    setMessages([...messages, { sender: 'me', content: message }]);
    setMessage('');
  };

  return (
    <div style={{ display: 'flex', height: '80vh' }}>
      <div style={{ width: '200px', borderRight: '1px solid gray' }}>
        <h3>Online Users</h3>
        {onlineUsers.map(id => (
          <div key={id}>
            <button onClick={() => setSelectedUser(id)}>{id}</button>
          </div>
        ))}
      </div>

      <div style={{ flex: 1, padding: '10px' }}>
        <h3>Chat</h3>
        <div style={{ height: '300px', overflowY: 'scroll', backgroundColor: '#f0f0f0', padding: '10px' }}>
          {messages.map((msg, i) => (
            <p key={i}><strong>{msg.sender === 'me' ? 'You' : 'Friend'}:</strong> {msg.content}</p>
          ))}
        </div>
        <div style={{ marginTop: '10px' }}>
          <input value={message} onChange={(e) => setMessage(e.target.value)} placeholder="Type a message" />
          <button onClick={handleSend}>Send</button>
        </div>
      </div>
    </div>
  );
}

5. 로그인 후 Socket 연결하기

// 예: /app/layout.tsx
import { SocketProvider } from '@/contexts/SocketContext';

export default function Layout({ children }: { children: React.ReactNode }) {
  const userId = typeof window !== 'undefined' ? localStorage.getItem('userId') || '' : '';

  return (
    <SocketProvider userId={userId}>
      {children}
    </SocketProvider>
  );
}
설명: 로그인할 때 localStorage.setItem('userId', user._id)를 꼭 저장해줘야 해.

예쁜 UI를 위한 팁
styled-components 또는 Tailwind CSS를 사용하면 디자인이 훨씬 이뻐질 수 있어.

다음 단계에서 Tailwind를 적용해서 다시 리팩토링해줄게!

이제 우리가 만든 실시간 채팅에 다음 기능을 추가할 거야:

Tailwind CSS로 멋진 스타일링

메시지 저장 (MongoDB에 대화 내용 저장)

채팅 알림 및 읽음 표시 기능

1. Tailwind CSS 설치 및 설정

① 설치 명령어:
npm install -D tailwindcss postcss autoprefixer
npx tailwindcss init -p

② tailwind.config.js 설정:

/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx}",
    "./components/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}

③ globals.css 적용:
@tailwind base;
@tailwind components;
@tailwind utilities;

2. 예쁜 채팅 UI로 리팩토링 (/app/chat/page.tsx)

'use client';

import { useEffect, useState } from 'react';
import { useSocket } from '@/contexts/SocketContext';

interface Message {
  sender: string;
  content: string;
}

export default function ChatPage() {
  const { socket, onlineUsers } = useSocket();
  const [selectedUser, setSelectedUser] = useState<string | null>(null);
  const [message, setMessage] = useState('');
  const [messages, setMessages] = useState<Message[]>([]);

  useEffect(() => {
    if (!socket) return;

    socket.on('receive_message', (msg: Message) => {
      setMessages(prev => [...prev, msg]);
    });

    return () => {
      socket.off('receive_message');
    };
  }, [socket]);

  const handleSend = () => {
    if (!selectedUser || !message) return;
    socket.emit('send_message', {
      sender: socket.id,
      receiver: selectedUser,
      content: message,
    });

    setMessages([...messages, { sender: 'me', content: message }]);
    setMessage('');
  };

  return (
    <div className="flex h-screen">
      <aside className="w-1/4 bg-gray-900 text-white p-4">
        <h2 className="text-xl mb-4">Online Users</h2>
        {onlineUsers.map(id => (
          <button
            key={id}
            onClick={() => setSelectedUser(id)}
            className="block w-full text-left p-2 mb-2 bg-gray-700 hover:bg-gray-600 rounded"
          >
            {id}
          </button>
        ))}
      </aside>

      <main className="flex-1 p-6 flex flex-col">
        <div className="flex-1 overflow-y-auto mb-4 bg-gray-100 rounded p-4">
          {messages.map((msg, i) => (
            <div
              key={i}
              className={`mb-2 ${msg.sender === 'me' ? 'text-right' : 'text-left'}`}
            >
              <span
                className={`inline-block px-3 py-2 rounded ${
                  msg.sender === 'me' ? 'bg-blue-500 text-white' : 'bg-gray-300'
                }`}
              >
                {msg.content}
              </span>
            </div>
          ))}
        </div>

        <div className="flex">
          <input
            className="flex-1 p-2 border rounded-l"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            placeholder="Type your message..."
          />
          <button
            className="bg-blue-500 text-white px-4 rounded-r"
            onClick={handleSend}
          >
            Send
          </button>
        </div>
      </main>
    </div>
  );
}

3. 메시지 저장 기능 (MongoDB)

① Message 모델 생성 (/models/Message.ts)

import mongoose from 'mongoose';

const messageSchema = new mongoose.Schema({
  sender: { type: String, required: true },
  receiver: { type: String, required: true },
  content: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  read: { type: Boolean, default: false }
});

export default mongoose.models.Message || mongoose.model('Message', messageSchema);

② chatHandlers.ts 수정 (메시지 저장 포함)

import { Server, Socket } from 'socket.io';
import Message from '../models/Message';

export const setupChatHandlers = (socket: Socket, io: Server) => {
  socket.on('send_message', async (data) => {
    const { sender, receiver, content } = data;

    // MongoDB에 메시지 저장
    const message = new Message({ sender, receiver, content });
    await message.save();

    // 상대방에게 전송
    io.to(receiver).emit('receive_message', { sender, content });
  });

  socket.on('join', (userId: string) => {
    socket.join(userId);
  });
};

③ 대화 불러오기 API (/routes/messages.ts)

router.get('/history/:userId', authMiddleware, async (req, res) => {
  const me = req.user.userId;
  const other = req.params.userId;

  const messages = await Message.find({
    $or: [
      { sender: me, receiver: other },
      { sender: other, receiver: me }
    ]
  }).sort({ timestamp: 1 });

  res.json(messages);
});

4. 알림 및 읽음 표시 기능 (기본 구조)

① 읽음 상태 업데이트

router.post('/read/:userId', authMiddleware, async (req, res) => {
  const me = req.user.userId;
  const other = req.params.userId;

  await Message.updateMany(
    { sender: other, receiver: me, read: false },
    { $set: { read: true } }
  );

  res.json({ message: 'Messages marked as read' });
});

② 클라이언트에서 읽음 처리 요청

const markAsRead = async () => {
  if (!selectedUser) return;
  await axios.post(`/messages/read/${selectedUser}`, {}, {
    headers: { Authorization: `Bearer ${getToken()}` },
  });
};
이 함수는 상대방 대화를 열었을 때 호출해줘.

✅ 오늘의 기능
채팅방 리스트 UI

이미지 전송

메시지 삭제

스티커 전송

메시지에 이모지 반응 달기

우선 채팅방 리스트부터 시작하고, 그다음 전송/삭제/반응 기능으로 넘어갈게!

✅ 1. 채팅방 리스트 UI
📦 서버: /models/Conversation.ts

import mongoose from 'mongoose';

const conversationSchema = new mongoose.Schema({
  members: [{ type: String, required: true }],
  lastMessage: {
    content: String,
    timestamp: Date,
  }
});

export default mongoose.models.Conversation || mongoose.model('Conversation', conversationSchema);
💡 members 배열에 대화 참여자 두 명의 userId를 저장해.

📦 서버: 메시지 저장 시 대화 업데이트

import Conversation from '../models/Conversation';

// send_message 이벤트 내부에서
await Conversation.findOneAndUpdate(
  { members: { $all: [sender, receiver] } },
  {
    members: [sender, receiver],
    lastMessage: {
      content,
      timestamp: new Date()
    }
  },
  { upsert: true, new: true }
);

📦 API: 모든 대화 가져오기

router.get('/conversations', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  const convos = await Conversation.find({
    members: userId
  }).sort({ 'lastMessage.timestamp': -1 });

  res.json(convos);
});

💻 클라이언트: /app/chatlist/page.tsx

'use client';

import { useEffect, useState } from 'react';
import axios from '@/lib/api';
import { getToken } from '@/lib/auth';

interface Conversation {
  _id: string;
  members: string[];
  lastMessage: {
    content: string;
    timestamp: string;
  };
}

export default function ChatListPage() {
  const [conversations, setConversations] = useState<Conversation[]>([]);

  useEffect(() => {
    const fetchConversations = async () => {
      const res = await axios.get('/messages/conversations', {
        headers: { Authorization: `Bearer ${getToken()}` }
      });
      setConversations(res.data);
    };
    fetchConversations();
  }, []);

  return (
    <div className="p-6">
      <h2 className="text-2xl mb-4 font-bold">My Chats</h2>
      <ul className="space-y-4">
        {conversations.map((c) => (
          <li key={c._id} className="p-4 rounded bg-gray-100 shadow hover:bg-gray-200">
            <p className="font-medium">Chat with: {c.members.join(', ')}</p>
            <p className="text-sm text-gray-600">Last: {c.lastMessage.content}</p>
          </li>
        ))}
      </ul>
    </div>
  );
}

✅ 2. 이미지 전송 기능

📦 백엔드: Multer로 이미지 저장

npm install multer

// routes/upload.ts
import multer from 'multer';

const storage = multer.diskStorage({
  destination: 'uploads/',
  filename: (_, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ storage });

router.post('/image', upload.single('image'), (req, res) => {
  res.json({ url: `/uploads/${req.file.filename}` });
});

💻 클라이언트: 이미지 전송 추가

<input type="file" onChange={handleImageUpload} />

const handleImageUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
  const file = e.target.files?.[0];
  if (!file) return;

  const formData = new FormData();
  formData.append('image', file);

  const res = await axios.post('/messages/image', formData, {
    headers: { Authorization: `Bearer ${getToken()}` }
  });

  socket.emit('send_message', {
    sender: myId,
    receiver: selectedUser,
    content: res.data.url,
    type: 'image'
  });
};
type: 'image'로 메시지 타입을 구분해!

✅ 3. 메시지 삭제 기능

📦 서버: 메시지 삭제 API

router.delete('/messages/:id', authMiddleware, async (req, res) => {
  const msg = await Message.findById(req.params.id);
  if (!msg || msg.sender !== req.user.userId) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  await msg.deleteOne();
  res.json({ message: 'Message deleted' });
});

💻 클라이언트: 메시지 옆에 삭제 버튼 추가

<button
  onClick={() => deleteMessage(msg._id)}
  className="text-sm text-red-500 ml-2"
>
  🗑️
</button>

const deleteMessage = async (id: string) => {
  await axios.delete(`/messages/${id}`, {
    headers: { Authorization: `Bearer ${getToken()}` }
  });
  setMessages(messages.filter(m => m._id !== id));
};

✅ 4. 스티커 전송 기능

const stickers = ['/stickers/1.png', '/stickers/2.png'];

return (
  <div className="flex space-x-2 mt-2">
    {stickers.map((url, idx) => (
      <img
        key={idx}
        src={url}
        className="w-12 h-12 cursor-pointer"
        onClick={() =>
          socket.emit('send_message', {
            sender: myId,
            receiver: selectedUser,
            content: url,
            type: 'sticker'
          })
        }
      />
    ))}
  </div>
);
서버는 이미지와 동일하게 처리해도 돼.

✅ 5. 이모지 반응 기능

const reactions = ['❤️', '😂', '👍', '😲'];

return (
  <div className="flex space-x-1">
    {reactions.map((r, i) => (
      <button key={i} onClick={() => reactToMessage(msg._id, r)}>
        {r}
      </button>
    ))}
  </div>
);

📦 서버: 메시지에 리액션 추가

const messageSchema = new mongoose.Schema({
  ...
  reactions: [{ emoji: String, userId: String }]
});

✅ 오늘 만들 기능
파일 전송 기능 (PDF, DOCX 등)

메시지 편집 기능

타자 중 표시 기능 (Typing Indicator)

각 기능은 백엔드와 프론트엔드를 연동해서 전체 흐름을 이해할 수 있도록 해줄게.

✅ 1. 파일 전송 기능

📦 백엔드: /routes/messages.ts

import multer from 'multer';
import path from 'path';

const storage = multer.diskStorage({
  destination: 'uploads/',
  filename: (_, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ storage });

router.post('/upload', upload.single('file'), (req, res) => {
  res.json({ url: `/uploads/${req.file.filename}`, name: req.file.originalname });
});

💻 프론트엔드:

<input type="file" onChange={handleFileUpload} />

const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
  const file = e.target.files?.[0];
  if (!file) return;

  const formData = new FormData();
  formData.append('file', file);

  const res = await axios.post('/messages/upload', formData, {
    headers: { Authorization: `Bearer ${getToken()}` },
  });

  socket.emit('send_message', {
    sender: myId,
    receiver: selectedUser,
    content: res.data.url,
    type: 'file',
    filename: res.data.name
  });
};

💬 메시지 렌더링 시 파일 링크 표시

{msg.type === 'file' ? (
  <a href={msg.content} download className="text-blue-500 underline">
    📎 {msg.filename}
  </a>
) : (
  <span>{msg.content}</span>
)}

✅ 2. 메시지 편집 기능

📦 백엔드: 메시지 편집 API

router.put('/messages/:id', authMiddleware, async (req, res) => {
  const msg = await Message.findById(req.params.id);
  if (!msg || msg.sender !== req.user.userId) {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  msg.content = req.body.content;
  msg.edited = true;
  await msg.save();

  res.json(msg);
});

💻 프론트엔드:

<button onClick={() => setEditing(msg._id)}>✏️</button>

{editing === msg._id ? (
  <div>
    <input value={editText} onChange={(e) => setEditText(e.target.value)} />
    <button onClick={() => saveEdit(msg._id)}>Save</button>
  </div>
) : (
  <span>{msg.content} {msg.edited && <i>(edited)</i>}</span>
)}

const saveEdit = async (id: string) => {
  const res = await axios.put(`/messages/${id}`, { content: editText }, {
    headers: { Authorization: `Bearer ${getToken()}` }
  });
  updateMessageInList(res.data); // 메시지 상태 업데이트
  setEditing(null);
};

✅ 3. 타자 중 표시 기능 (Typing Indicator)

📦 서버: chatHandlers.ts에 추가
socket.on('typing', ({ from, to }) => {
  io.to(to).emit('typing', from);
});

💻 프론트엔드:

useEffect(() => {
  if (!socket) return;

  socket.on('typing', (from: string) => {
    setTypingUser(from);
    setTimeout(() => setTypingUser(null), 2000); // 2초 후 사라짐
  });

  return () => {
    socket.off('typing');
  };
}, [socket]);

const handleTyping = () => {
  socket.emit('typing', { from: myId, to: selectedUser });
};

<input onChange={(e) => { setMessage(e.target.value); handleTyping(); }} />
{typingUser && <p className="text-sm text-gray-400">{typingUser} is typing...</p>}

✅ 오늘 만들 기능
읽음 시간 표시

메시지 전송 상태 (보냄, 도달, 읽음)

다크 모드 지원

✅ 1. 읽음 시간 표시

📦 서버: Message 모델에 readAt 추가

readAt: { type: Date, default: null }

📦 API: 메시지를 읽을 때 readAt 기록

await Message.updateMany(
  { sender: other, receiver: me, read: false },
  { $set: { read: true, readAt: new Date() } }
);

💻 프론트엔드: 메시지 아래 읽음 시간 표시

{msg.readAt && (
  <p className="text-xs text-gray-400 mt-1">
    Read at: {new Date(msg.readAt).toLocaleTimeString()}
  </p>
)}
💡 readAt이 있는 경우에만 표시되고, 시간만 보여줘.

✅ 2. 메시지 전송 상태 표시
우리는 상태를 세 가지로 나눠서 표시할 수 있어:

sent: 내가 보냄

delivered: 상대방이 socket 방에 들어와 있음

read: 상대방이 읽었음

📦 서버: 메시지 상태별 브로드캐스트

socket.on('send_message', async (data) => {
  const message = new Message({ ...data });
  await message.save();

  io.to(data.receiver).emit('receive_message', message);

  // 메시지 도달 확인
  io.to(data.sender).emit('message_status', {
    id: message._id,
    status: 'delivered'
  });
});

💻 프론트엔드:

useEffect(() => {
  socket.on('message_status', ({ id, status }) => {
    updateMessageStatus(id, status);
  });

  return () => {
    socket.off('message_status');
  };
}, []);

<p className="text-xs text-gray-400 mt-1">
  {msg.status === 'read'
    ? '✔✔ Read'
    : msg.status === 'delivered'
    ? '✔✔ Delivered'
    : '✔ Sent'}
</p>

✅ 3. 다크 모드 지원

① Tailwind 설정 변경

// tailwind.config.js
module.exports = {
  darkMode: 'class',
  ...
}

② 전역 테마 상태 만들기

// /contexts/ThemeContext.tsx
'use client';

import { createContext, useContext, useEffect, useState } from 'react';

const ThemeContext = createContext<any>(null);

export const ThemeProvider = ({ children }: { children: React.ReactNode }) => {
  const [dark, setDark] = useState(false);

  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark);
  }, [dark]);

  return (
    <ThemeContext.Provider value={{ dark, setDark }}>
      {children}
    </ThemeContext.Provider>
  );
};

export const useTheme = () => useContext(ThemeContext);

③ 다크 모드 토글 버튼

const { dark, setDark } = useTheme();

<button onClick={() => setDark(!dark)}>
  {dark ? '🌞 Light Mode' : '🌙 Dark Mode'}
</button>

④ Tailwind 클래스 적용 예시

<div className="bg-white dark:bg-gray-900 text-black dark:text-white">
  {/* 채팅 화면 */}
</div>
