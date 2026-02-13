import chat.*;
import com.google.gson.Gson;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.SecretKey;

public class TcpServer {
    public static final List<ClientHandler> clients = new ArrayList<>();
    public static final ConcurrentHashMap<Integer, List<NetworkPacket>> offlineBuffer = new ConcurrentHashMap<>();

    public static final Gson gson = new Gson();
    public static volatile KeyPair globalServerKyberKeys;

    public static void main(String[] args){
        try {
            globalServerKyberKeys = CryptoHelper.generateKyberKeys();
            System.out.println("SERVER PORNIT");

            startKeyRotation();
            new Thread(TcpServer::tcpServer).start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void startKeyRotation() {
        new Thread(() -> {
            while (true) {
                try {

                    Thread.sleep(30 * 60 * 1000);

                    System.out.println("🔄 [ROTATION] Generare chei Kyber noi...");
                    long start = System.currentTimeMillis();

                    // Aici generam cheia noua. Dureaza putin, dar nu blocheaza clientii conectati!
                    KeyPair newKeys = CryptoHelper.generateKyberKeys();

                    // O schimbam atomic
                    globalServerKyberKeys = newKeys;

                    System.out.println("✅ [ROTATION] Chei schimbate in " + (System.currentTimeMillis() - start) + "ms. Urmatoarea rotire in 30 min.");

                    // Asteptam 30 minute (1800000 ms) sau cat vrei tu
                    Thread.sleep(30 * 60 * 1000);

                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }).start();
    }

    public static void tcpServer(){
        try(ServerSocket serverSocket = new ServerSocket(15555)){
            while (true){
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client conectat: " + clientSocket.getInetAddress());

                ClientHandler handler = new ClientHandler(clientSocket);
                new Thread(handler).start();
            }
        } catch (IOException e) {
            System.out.println("EROARE PORT 15555: " + e.getMessage());
        }
    }

    static class ClientHandler implements Runnable{
        private Socket socket;
//        private ObjectOutputStream out;
//        private ObjectInputStream in;
        private PrintWriter out;
        private BufferedReader in;

        private User currentUser = null;
        private int currentChatId = -1;
        private boolean isRunning = true;

        private SecretKey sessionKey = null;
        private PrivateKey tempKyberPrivate = null;

        public ClientHandler(Socket socket) {
            this.socket = socket;
            try{
//                this.out = new ObjectOutputStream(socket.getOutputStream());
//                this.in = new ObjectInputStream(socket.getInputStream());

                socket.setTcpNoDelay(true);

                this.out = new PrintWriter(socket.getOutputStream(), true);
                this.in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        private boolean isExemptFromTunnel(PacketType type) {
            return type == PacketType.SEND_MESSAGE ||
                    type == PacketType.RECEIVE_MESSAGE ||
                    type == PacketType.GET_MESSAGES_RESPONSE ||
                    type == PacketType.EXCHANGE_SESSION_KEY ||
                    type == PacketType.EDIT_MESSAGE_BROADCAST ||
                    type == PacketType.DELETE_MESSAGE_BROADCAST;
        }

        @Override
        public void run() {
            try {
                if (!performHandshake()) {
                    System.out.println("Handshake Esuat.");
                    disconnect();
                    return;
                }

                while (isRunning) {
//                    String jsonRequest = (String) in.readObject();
                    String jsonRequest = in.readLine();
                    if(jsonRequest==null){
                        break;
                    }

                    NetworkPacket packet = NetworkPacket.fromJson(jsonRequest);

                    if (packet.getType() == PacketType.SECURE_ENVELOPE) {
                        try {
                            String encryptedPayload = packet.getPayload().getAsString();
                            byte[] packedBytes = Base64.getDecoder().decode(encryptedPayload);

                            System.out.println("ENCRYPTED DATA: " + encryptedPayload);

                            String originalJson = CryptoHelper.unpackAndDecrypt(sessionKey, packedBytes);
                            packet = NetworkPacket.fromJson(originalJson);

                            System.out.println("Pachet Real: " + originalJson);

                        } catch (Exception e) {
                            System.out.println("Eroare decriptare Tunel!");
                            continue;
                        }
                    }
                    else if (isExemptFromTunnel(packet.getType())) {
                        // Pass-through ok
                    }
                    else {
                        System.out.println("Pachet necriptat refuzat: " + packet.getType());
                        continue;
                    }

                    switch (packet.getType()) {
                        case LOGIN_REQUEST: handleLogin(packet); break;
                        case REGISTER_REQUEST: handleRegister(packet); break;

                        case EXCHANGE_SESSION_KEY: handleSessionKeyExchange(packet); break;
                        case SEND_MESSAGE: handleSendMessage(packet); break;

                        case GET_CHATS_REQUEST: handleGetChats(); break;
                        case GET_USERS_REQUEST: handleGetUsersForAdd(); break;
                        case CREATE_CHAT_REQUEST: handleCreateChat(packet); break;
                        case DELETE_CHAT_REQUEST: handleDeleteChat(packet); break;
                        case RENAME_CHAT_REQUEST: handleRenameChat(packet); break;
                        case ENTER_CHAT_REQUEST: handleEnterChat(packet); break;
                        case EXIT_CHAT_REQUEST:
                            this.currentChatId = -1;
                            sendPacket(PacketType.EXIT_CHAT_RESPONSE, "BYE");
                            break;

                        case EDIT_MESSAGE_REQUEST: handleEditMessage(packet); break;
                        case DELETE_MESSAGE_REQUEST: handleDeleteMessage(packet); break;
                        case LOGOUT: disconnect(); break;

                        default: System.out.println("Unknown packet: " + packet.getType());
                    }
                }
            } catch (Exception e) {
                disconnect();
            }
        }

        private void handleLogin(NetworkPacket packet) throws IOException {
            ChatDtos.AuthDto dto = gson.fromJson(packet.getPayload(), ChatDtos.AuthDto.class);
            User user = Database.selectUserByUsername(dto.username);

            if (user != null && PasswordUtils.verifyPassword(dto.password, user.getSalt(), user.getPasswordHash())) {
                synchronized (clients) {
                    for (ClientHandler c : clients) {
                        if (c.currentUser != null && c.currentUser.getId() == user.getId()) {
                            sendPacket(PacketType.LOGIN_RESPONSE, "ALREADY"); return;
                        }
                    }
                    clients.add(this);
                }
                this.currentUser = user;
                Database.insertUserLog(user.getId(), "LOGIN", System.currentTimeMillis(), socket.getInetAddress().getHostAddress());
                sendPacket(PacketType.LOGIN_RESPONSE, user);

                List<NetworkPacket> pending = offlineBuffer.remove(user.getId());

                if (pending != null && !pending.isEmpty()) {
                    System.out.println("[SYNC] User " + user.getId() + " online. Livram " + pending.size() + " pachete din buffer.");
                    for (NetworkPacket p : pending) {
                        sendDirectPacket(p);
                        try { Thread.sleep(10); } catch (InterruptedException e) {}
                    }
                }

            } else {
                sendPacket(PacketType.LOGIN_RESPONSE, "FAIL");
            }
        }

        private void handleSessionKeyExchange(NetworkPacket packet) throws IOException {
            ChatDtos.SessionKeyDto keyDto = gson.fromJson(packet.getPayload(), ChatDtos.SessionKeyDto.class);

            System.out.println("\n[KEY EXCHANGE START]");
            System.out.println("Sender (Eu): " + currentUser.getId() + " (" + currentUser.getUsername() + ")");
            System.out.println("Chat ID: " + keyDto.chatId);

            List<GroupMember> members = Database.selectGroupMembersByChatId(keyDto.chatId);

            if (members == null || members.isEmpty()) {
                System.out.println("EROARE: Niciun membru in DB pentru chat-ul asta!");
                return;
            }

            System.out.println("Membri gasiti in DB: " + members.size());

            int targetId = -1;
            for (GroupMember m : members) {
                System.out.println("? Verific ID: " + m.getUserId());
                if (m.getUserId() != currentUser.getId()) {
                    targetId = m.getUserId();
                    System.out.println("ASTA E PARTENERUL! (ID: " + targetId + ")");
                    break;
                } else {
                    System.out.println("SKIP (Sunt eu)");
                }
            }

            if (targetId == -1) {
                System.out.println("EROARE: Nu am gasit niciun partener (poate esti singur in grup?)");
                return;
            }

            boolean sent = false;
            NetworkPacket forwardPacket = new NetworkPacket(PacketType.EXCHANGE_SESSION_KEY, currentUser.getId(), keyDto);

            synchronized (clients) {
                for (ClientHandler client : clients) {
                    if (client.currentUser != null && client.currentUser.getId() == targetId) {
                        client.sendDirectPacket(forwardPacket);
                        sent = true;
                        System.out.println("[KEY] Cheie livrata LIVE catre Socket-ul lui User " + targetId);
                        break;
                    }
                }
            }

            if (!sent) {
                System.out.println("[KEY] User " + targetId + " e OFFLINE. Bag cheia in Buffer.");
                offlineBuffer.computeIfAbsent(targetId, k -> new ArrayList<>()).add(forwardPacket);
                System.out.println("Buffer size pt user " + targetId + ": " + offlineBuffer.get(targetId).size());
            }
            System.out.println("[KEY EXCHANGE END]\n");
        }

        private void handleSendMessage(NetworkPacket packet) throws IOException {
            Message receivedMsg = gson.fromJson(packet.getPayload(), Message.class);
            if (currentChatId == -1) return;

            long timestamp = System.currentTimeMillis();

            System.out.println("[MESSAGE ROUTING] Am primit un mesaj de la User " + currentUser.getId());

            int msgId = Database.insertMessageReturningId(
                    receivedMsg.getContent(),
                    timestamp,
                    currentUser.getId(),
                    currentChatId
            );

            Message fullMsg = new Message(msgId, receivedMsg.getContent(), timestamp, currentUser.getId(), currentChatId);

            String encryptedPreview = Base64.getEncoder().encodeToString(fullMsg.getContent());
            System.out.println("CONTINUT (SERVERUL VEDE DOAR ASTA): " + encryptedPreview);

            broadcastToPartner(currentChatId, PacketType.RECEIVE_MESSAGE, fullMsg);

            sendPacket(PacketType.RECEIVE_MESSAGE, fullMsg);
        }

        private void broadcastToPartner(int chatId, PacketType type, Object payload) {
            List<GroupMember> members = Database.selectGroupMembersByChatId(chatId);

            for (GroupMember m : members) {
                int targetId = m.getUserId();
                if (targetId == currentUser.getId()) continue;

                boolean sent = false;

                NetworkPacket p = new NetworkPacket(type, currentUser.getId(), payload);

                synchronized (clients) {
                    for (ClientHandler client : clients) {
                        if (client.currentUser != null && client.currentUser.getId() == targetId) {
                            try {
                                client.sendDirectPacket(p);
                                sent = true;
                            } catch (IOException e) {}
                            break;
                        }
                    }
                }

                if (!sent) {
                    System.out.println("[MSG] User " + targetId + " offline. Mesaj salvat in Buffer.");
                    offlineBuffer.computeIfAbsent(targetId, k -> new ArrayList<>()).add(p);
                }
            }
        }

        private boolean performHandshake() {
            try {
                System.out.println("Handshake...");

//                KeyPair kyberPair = CryptoHelper.generateKyberKeys();
                KeyPair kyberPair = TcpServer.globalServerKyberKeys;
                KeyPair ecPair = CryptoHelper.generateECKeys();

                this.tempKyberPrivate = kyberPair.getPrivate();
                byte[] pubBytes = kyberPair.getPublic().getEncoded();

                String pubBase64 = Base64.getEncoder().encodeToString(pubBytes);
                String ecPubBase64 = Base64.getEncoder().encodeToString(ecPair.getPublic().getEncoded());

                String combinedPayload = pubBase64 + ":" + ecPubBase64;

                NetworkPacket hello = new NetworkPacket(PacketType.KYBER_SERVER_HELLO, 0, combinedPayload);
//                synchronized (out) { out.writeObject(hello.toJson()); out.flush(); }
                synchronized (out){
                    out.println(hello.toJson());
                    out.flush();
                }

//                String responseJson = (String) in.readObject();
                String responseJson = in.readLine();
                NetworkPacket response = NetworkPacket.fromJson(responseJson);

                if (response.getType() == PacketType.KYBER_CLIENT_FINISH) {
                    String payload = response.getPayload().getAsString();
                    String[] parts = payload.split(":");

                    byte[] kyberCipherBytes = Base64.getDecoder().decode(parts[0]);
                    byte[] clientECPubBytes = Base64.getDecoder().decode(parts[1]);

                    SecretKey kyberSecret = CryptoHelper.decapsulate(this.tempKyberPrivate, kyberCipherBytes);

                    PublicKey clientECPub = CryptoHelper.decodeECPublicKey(clientECPubBytes);
                    byte[] ecSecret = CryptoHelper.doECDH(ecPair.getPrivate(), clientECPub);

                    this.sessionKey = CryptoHelper.combineSecrets(ecSecret, kyberSecret.getEncoded());
                    this.tempKyberPrivate = null;
                    System.out.println("Tunel OK!");
                    return true;
                }
                return false;
            } catch (Exception e) { return false; }
        }

        private void sendPacket(PacketType type, Object payload) throws IOException {
            int myId = (currentUser != null) ? currentUser.getId() : 0;
            NetworkPacket p = new NetworkPacket(type, myId, payload);
            sendDirectPacket(p);
        }

        private void sendDirectPacket(NetworkPacket p) throws IOException {
            if (isExemptFromTunnel(p.getType())) {
//                synchronized (out) { out.writeObject(p.toJson()); out.flush(); }
                synchronized (out) { out.println(p.toJson()); out.flush(); }
            } else if (sessionKey != null) {
                try {
                    String clearJson = p.toJson();
                    byte[] encryptedBytes = CryptoHelper.encryptAndPack(sessionKey, clearJson);
                    String encryptedBase64 = Base64.getEncoder().encodeToString(encryptedBytes);
                    NetworkPacket envelope = new NetworkPacket(PacketType.SECURE_ENVELOPE, p.getSenderId(), encryptedBase64);
//                    synchronized (out) { out.writeObject(envelope.toJson()); out.flush(); }
                    synchronized (out) { out.println(envelope.toJson()); out.flush(); }
                } catch (Exception e) { e.printStackTrace(); }
            } else {
//                synchronized (out) { out.writeObject(p.toJson()); out.flush(); }
                synchronized (out) { out.println(p.toJson()); out.flush(); }
            }
        }

        // Standard handlers
        private void handleRegister(NetworkPacket packet) throws IOException {
            ChatDtos.AuthDto dto = gson.fromJson(packet.getPayload(), ChatDtos.AuthDto.class);
            if (Database.selectUserByUsername(dto.username) != null) { sendPacket(PacketType.REGISTER_RESPONSE, "EXISTS"); return; }
            String salt = PasswordUtils.generateSalt(50);
            String hash = PasswordUtils.hashPassword(dto.password, salt);
            Database.insertUser(dto.username, hash, salt, System.currentTimeMillis());
            User newUser = Database.selectUserByUsername(dto.username);
            this.currentUser = newUser;
            synchronized (clients) { clients.add(this); }
            sendPacket(PacketType.REGISTER_RESPONSE, newUser);
        }
        private void handleGetChats() throws IOException { if (currentUser != null) sendPacket(PacketType.GET_CHATS_RESPONSE, Database.selectGroupChatsByUserId(currentUser.getId())); }
        private void handleGetUsersForAdd() throws IOException {
            List<String> rawUsers = Database.selectUsersAddConversation();
            List<String> filtered = new ArrayList<>();
            for (String u : rawUsers) { int uid = Integer.parseInt(u.split(",")[0]); if (uid != currentUser.getId() && uid != -1) filtered.add(u); }
            sendPacket(PacketType.GET_USERS_RESPONSE, filtered);
        }

        private void handleEnterChat(NetworkPacket packet) throws IOException {
            int chatId = gson.fromJson(packet.getPayload(), Integer.class);
            this.currentChatId = chatId;
            sendPacket(PacketType.ENTER_CHAT_RESPONSE, "OK");
            List<Message> history = Database.selectMessagesByGroup(chatId);
            sendPacket(PacketType.GET_MESSAGES_RESPONSE, history);
        }

        private void handleCreateChat(NetworkPacket packet) throws IOException {
            ChatDtos.CreateGroupDto dto = gson.fromJson(packet.getPayload(), ChatDtos.CreateGroupDto.class);
            Database.insertGroupChat(dto.groupName);
            GroupChat newChat = Database.selectGroupChatByName(dto.groupName);

            if (newChat != null) {
                Database.insertGroupMember(newChat.getId(), currentUser.getId());
                Database.insertGroupMember(newChat.getId(), dto.targetUserId);

                NetworkPacket broadcastPacket = new NetworkPacket(PacketType.CREATE_CHAT_BROADCAST, currentUser.getId(), newChat);
                sendDirectPacket(broadcastPacket);

                sendToSpecificUser(dto.targetUserId, broadcastPacket);
            }
        }

        private void handleRenameChat(NetworkPacket packet) throws IOException {
            ChatDtos.RenameGroupDto dto = gson.fromJson(packet.getPayload(), ChatDtos.RenameGroupDto.class);

            Database.updateGroupChatName(dto.chatId, dto.newName);
            NetworkPacket broadcastPacket = new NetworkPacket(PacketType.RENAME_CHAT_BROADCAST, currentUser.getId(), dto);

            sendDirectPacket(broadcastPacket);
            broadcastToChatMembers(dto.chatId, PacketType.RENAME_CHAT_BROADCAST, dto);
        }

        private void handleDeleteChat(NetworkPacket packet) throws IOException {
            int chatId = gson.fromJson(packet.getPayload(), Integer.class);

            List<GroupMember> members = Database.selectGroupMembersByChatId(chatId);
            Database.deleteGroupChatTransactional(chatId);

            NetworkPacket broadcastPacket = new NetworkPacket(PacketType.DELETE_CHAT_BROADCAST, currentUser.getId(), chatId);
            sendDirectPacket(broadcastPacket);

            if (members != null) {
                for (GroupMember m : members) {
                    if (m.getUserId() != currentUser.getId()) {
                        sendToSpecificUser(m.getUserId(), broadcastPacket);
                    }
                }
            }
        }

        private void sendToSpecificUser(int targetUserId, NetworkPacket p) {
            synchronized (clients) {
                for (ClientHandler client : clients) {
                    if (client.currentUser != null && client.currentUser.getId() == targetUserId) {
                        try { client.sendDirectPacket(p); } catch (Exception e) {}
                        break;
                    }
                }
            }
        }

        private void broadcastToChatMembers(int chatId, PacketType type, Object payload) {
            List<GroupMember> members = Database.selectGroupMembersByChatId(chatId);
            if (members == null) return;
            NetworkPacket p = new NetworkPacket(type, currentUser.getId(), payload);
            for (GroupMember m : members) {
                if (m.getUserId() != currentUser.getId()) {
                    sendToSpecificUser(m.getUserId(), p);
                }
            }
        }

        private void handleEditMessage(NetworkPacket packet) throws IOException {
            ChatDtos.EditMessageDto dto = gson.fromJson(packet.getPayload(), ChatDtos.EditMessageDto.class);
            if (Database.updateMessageById(dto.messageId, dto.newContent)) {
                if (currentChatId != -1) {
                    broadcastToPartner(currentChatId, PacketType.EDIT_MESSAGE_BROADCAST, dto);
                    sendPacket(PacketType.EDIT_MESSAGE_BROADCAST, dto);
                }
            }
        }
        private void handleDeleteMessage(NetworkPacket packet) throws IOException {
            int msgId = gson.fromJson(packet.getPayload(), Integer.class);
            if (Database.deleteMessageById(msgId)) {
                if (currentChatId != -1) {
                    broadcastToPartner(currentChatId, PacketType.DELETE_MESSAGE_BROADCAST, msgId);
                    sendPacket(PacketType.DELETE_MESSAGE_BROADCAST, msgId);
                }
            }
        }
        private void disconnect() {
            isRunning = false;
            synchronized (clients) { clients.remove(this); }
            try { socket.close(); } catch (IOException e) {}
            System.out.println("Client deconectat.");
        }
    }
}

