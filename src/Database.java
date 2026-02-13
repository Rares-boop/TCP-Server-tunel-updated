import chat.GroupChat;
import chat.GroupMember;
import chat.Message;
import chat.User;
import io.github.cdimascio.dotenv.Dotenv;

import javax.swing.*;
import java.math.BigInteger;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import chat.ChatDtos;

public class Database {
    public static Dotenv dotenv = Dotenv.load();
    public static String connString = "jdbc:postgresql://" + dotenv.get("DB_HOST")
            +":"+dotenv.get("DB_PORT")+"/"+dotenv.get("DB_DATABASE");
    public static String user = dotenv.get("DB_USER");
    public static String password = dotenv.get("DB_PASSWORD");
    public static void main(String[] args){
        System.out.println("DA");
        /*createTableUsers();
        createTableGroupChats();
        createTableGroupMembers();
        createTableUserLogs();
        createTableMessages();*/
        /*insertUser("user1","$argon2i$v=19$m=65536,t=3,p=2$ryHhVPoar5wPMpBAdGCfXg$/VpbEnvKt2wCNMK58uyNomrYgs8gvK0KLZ8b51Gf38U",
                "2VbHHVOhQajLbIJss2FkwzZOyMkXW6BCzkrD4Nue+QtwLPBN8/wsHjTaB1+JNPqcYyc=", System.currentTimeMillis());*/
        /*insertUser("user2","$argon2i$v=19$m=65536,t=3,p=2$1mrykwhmGo6va01bp45C1w$FV4ChiR+Y31WuhAyjUFdftIRxhuWIMb88e+ivK5Xur0",
                "1i4Y6GRQqzkyE9A6B7NtrlRXy1/gqjuBe8FPnCdWKcxNy3cewFX+1sbTK3pfvsM8vI4=", System.currentTimeMillis());*/
        /*insertUser("user3","$argon2i$v=19$m=65536,t=3,p=2$mwSOyb59h5biXPtf0dNg0A$Cgl9wFVeURUNKbQhF8TDfUDK6W/e0iSac8hcIe0ii1U",
                "UBlPPo40x0okq7RNbmUjitrWwtnLG37YRZ0l4dByctpoWAZRliHsCKuUMAMI/vOOMLU=", System.currentTimeMillis());*/
        //createTableExtras();
        selectUsers();
    }

    public static void createTableUsers(){
        try(var connection = DriverManager.getConnection(connString, user, password);
        var stmt = connection.createStatement()){

            String query = """
                    CREATE TABLE IF NOT EXISTS USERS(
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(100) NOT NULL,
                        password_hash VARCHAR(255) NOT NULL,
                        salt VARCHAR(100) NOT NULL,
                        created_at BIGINT
                    );
                    """;

            stmt.executeUpdate(query);

        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public static void selectUsers(){
        try(var connection = DriverManager.getConnection(connString, user, password);
        var stmt = connection.createStatement()){

            String query = "SELECT * FROM USERS";
            ResultSet rs = stmt.executeQuery(query);

            while (rs.next()){

                int id = rs.getInt("id");
                String username = rs.getString("username");
                String passwordHash = rs.getString("password_hash");
                String salt = rs.getString("salt");
                long createdAt = rs.getLong("created_at");


                System.out.println(id+" "+username);
            }

        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public static void insertUser(String username, String passwordHash,
                                  String salt, long createdAt){
        String query = """
            INSERT INTO users(username, password_hash, salt, created_at)
            VALUES (?, ?, ?, ?)
            """;

        try(var connection = DriverManager.getConnection(connString, user, password);
        PreparedStatement ps = connection.prepareStatement(query)){

            ps.setString(1,username);
            ps.setString(2,passwordHash);
            ps.setString(3,salt);
            ps.setLong(4, createdAt);

            ps.executeUpdate();
            System.out.println("User inserted succesfully ");

        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public static User selectUserByUsername(String usernameData){
        User userData = null;

        String query = """
                SELECT id, username, password_hash, salt, created_at
                FROM USERS WHERE username = ?;
               """;

        try(var connection = DriverManager.getConnection(connString, user, password);
        PreparedStatement ps = connection.prepareStatement(query)){

            ps.setString(1,usernameData);
            ResultSet rs = ps.executeQuery();

            if (rs.next()){

                int id = rs.getInt("id");
                String username = rs.getString("username");
                String passwordHash = rs.getString("password_hash");
                String salt = rs.getString("salt");
                long createdAt = rs.getLong("created_at");

                userData = new User(id, username, passwordHash, salt, createdAt);
            }

        } catch (SQLException e) {
            throw new RuntimeException(e);
        }

        return userData;
    }

    public static List<String> selectUsersAddConversation(){
        List<String> users = new ArrayList<>();

        String query = "SELECT id, username FROM USERS";

        try(var connection = DriverManager.getConnection(connString, user, password);
        var stmt = connection.createStatement()){

            ResultSet rs = stmt.executeQuery(query);
            while (rs.next()){
                int id = rs.getInt("id");
                String username = rs.getString("username");
                users.add(id + "," + username);
            }

        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return users;
    }

    public static void createTableUserLogs(){
        try(var connection = DriverManager.getConnection(connString, user, password);
        var stmt =connection.createStatement()){

                String query = """
                        CREATE TABLE IF NOT EXISTS USER_LOGS(
                            id SERIAL PRIMARY KEY,
                            id_user INTEGER,
                            action_type VARCHAR(100),
                            log_timestamp BIGINT,
                            ip_address VARCHAR(50),
                            FOREIGN KEY(id_user) REFERENCES USERS(id)
                        );
                        """;

                stmt.executeUpdate(query);

        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public static boolean insertUserLog(int userId, String actionType, long timestamp,
                                     String ipAddress){
        String query = """
                INSERT INTO USER_LOGS(id_user, action_type, log_timestamp, ip_address)
                VALUES(?, ?, ?, ?)
                """;
        try(var connection = DriverManager.getConnection(connString, user, password);
        PreparedStatement ps = connection.prepareStatement(query)){

            ps.setInt(1, userId);
            ps.setString(2, actionType);
            ps.setLong(3, timestamp);
            ps.setString(4, ipAddress);

            int rows = ps.executeUpdate();

            return rows > 0;

        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public static void createTableGroupMembers(){
        try(var connection = DriverManager.getConnection(connString, user, password);
        var stmt = connection.createStatement()){

            String query = """
                    CREATE TABLE IF NOT EXISTS GROUP_MEMBERS(
                        id_group INTEGER,
                        id_user INTEGER,
                        PRIMARY KEY(id_group, id_user),
                        FOREIGN KEY(id_group) REFERENCES GROUP_CHATS(id) ON DELETE CASCADE,
                        FOREIGN KEY(id_user) REFERENCES USERS(id) ON DELETE CASCADE
                    );
                    """;

                    stmt.executeUpdate(query);

        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public static List<GroupMember> selectAllGroupMembers(){
        List<GroupMember> groupMembers = new ArrayList<>();
        try(var connection = DriverManager.getConnection(connString, user, password);
        var stmt = connection.createStatement()){

            String query = "SELECT * FROM GROUP_MEMBERS";
            ResultSet rs = stmt.executeQuery(query);

            while (rs.next()){
                int userId = rs.getInt(1);
                int groupId = rs.getInt(2);

                groupMembers.add(new GroupMember(userId, groupId));
            }

        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return groupMembers;
    }

    public static List<GroupMember> selectGroupMembersByUserId(int userId){
        List<GroupMember> currentUserGroupMembers = new ArrayList<>();
        String query = "SELECT * FROM GROUP_MEMBERS WHERE id_user=?";
        try(var connection = DriverManager.getConnection(connString, user, password);
        PreparedStatement ps = connection.prepareStatement(query)){

            ps.setInt(1,userId);
            ResultSet rs = ps.executeQuery();

            while (rs.next()){
                int userIdDatabase = rs.getInt(1);
                int groupId = rs.getInt(2);

                currentUserGroupMembers.add(new GroupMember(userIdDatabase, groupId));
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return currentUserGroupMembers;
    }

    public static void insertGroupMember(int groupId, int userId){
        String query = """
                INSERT INTO GROUP_MEMBERS(id_group, id_user) VALUES(?, ?)""";

        try(var connection=DriverManager.getConnection(connString, user, password);
        PreparedStatement ps = connection.prepareStatement(query)){

            ps.setInt(1,groupId);
            ps.setInt(2, userId);

            ps.executeUpdate();
            System.out.println("GROUP MEMBER INSERTED "+userId);

        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public static List<GroupMember> selectGroupMembersByChatId(int groupId){
        List<GroupMember> currentChatGroupMembers = new ArrayList<>();
        String query = """
                SELECT id_group, id_user FROM GROUP_MEMBERS WHERE id_group = ?""";
        try(var connection = DriverManager.getConnection(connString, user, password);
        PreparedStatement ps = connection.prepareStatement(query)){

            ps.setInt(1, groupId);
            ResultSet rs = ps.executeQuery();

            while (rs.next()){
                int groupIdDatabase = rs.getInt(1);
                int userId = rs.getInt(2);

                currentChatGroupMembers.add(new GroupMember(groupIdDatabase, userId));
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }

        return  currentChatGroupMembers;
    }

    /*public static boolean deleteGroupMembersByChatId(int chatId){
        String query = "DELETE FROM GROUP_MEMBERS WHERE id_group = ?";
        try(var connection = DriverManager.getConnection(connString, user, password);
        PreparedStatement ps = connection.prepareStatement(query)){

            ps.setInt(1,chatId);
            int rows = ps.executeUpdate();

            return rows > 0;

        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }*/

    public static boolean deleteGroupChatTransactional(int chatId){
        String deleteMessages = "DELETE FROM MESSAGES WHERE id_group=?";
        String deleteGroupMembers = "DELETE FROM GROUP_MEMBERS WHERE id_group=?";

        String deleteGroupChat = "DELETE FROM GROUP_CHATS WHERE id=?";
        try(var connection = DriverManager.getConnection(connString, user, password)){
            connection.setAutoCommit(false);

            try(PreparedStatement psMessages = connection.prepareStatement(deleteMessages);
            PreparedStatement psGroupMembers = connection.prepareStatement(deleteGroupMembers);
            PreparedStatement psGroupChat = connection.prepareStatement(deleteGroupChat)){

                psMessages.setInt(1, chatId);
                psMessages.executeUpdate();

                psGroupMembers.setInt(1, chatId);
                psGroupMembers.executeUpdate();

                psGroupChat.setInt(1, chatId);
                int affectedRows = psGroupChat.executeUpdate();

                connection.commit();
                return affectedRows > 0;
            }
            catch (SQLException e){
                connection.rollback();
                throw e;
            }finally {
                connection.setAutoCommit(true);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public static void createTableGroupChats(){
        try(var connection = DriverManager.getConnection(connString, user, password);
        var stmt = connection.createStatement()){

            String query = """
                    CREATE TABLE IF NOT EXISTS GROUP_CHATS(
                        id SERIAL PRIMARY KEY,
                        name VARCHAR(200) NOT NULL
                    );
                    """;

                    stmt.executeUpdate(query);

        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public static List<GroupChat> selectAllGroupChats(){
        List<GroupChat> groupChats = new ArrayList<>();
        try(var connection = DriverManager.getConnection(connString, user, password);
        var stmt = connection.createStatement()){

            String query = "SELECT * FROM GROUP_CHATS";
            ResultSet rs = stmt.executeQuery(query);

            while (rs.next()){
                int id = rs.getInt(1);
                String name = rs.getString(2);

                groupChats.add(new GroupChat(id, name));
            }

        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return groupChats;
    }

    public static List<GroupChat> selectGroupChatsByUserId(int userId){
        List<GroupChat> currentUserGroupChats = new ArrayList<>();
        String query = """
                SELECT GROUP_CHATS.id, GROUP_CHATS.name
                FROM GROUP_CHATS JOIN GROUP_MEMBERS ON
                GROUP_CHATS.id = GROUP_MEMBERS.id_group
                WHERE id_user=?""";

        try(var connection = DriverManager.getConnection(connString, user, password);
        PreparedStatement ps = connection.prepareStatement(query)){

            ps.setInt(1, userId);
            ResultSet rs = ps.executeQuery();

            while (rs.next()){
                int id = rs.getInt(1);
                String name = rs.getString(2);

                currentUserGroupChats.add(new GroupChat(id, name));
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return currentUserGroupChats;
    }

    public static void insertGroupChat(String name){
        String query = """
                INSERT INTO GROUP_CHATS(name) VALUES(?)""";
        try(var connection =DriverManager.getConnection(connString, user, password);
        PreparedStatement ps = connection.prepareStatement(query)){

            ps.setString(1, name);

            ps.executeUpdate();
            System.out.println("GROUP CHAT INSERTED "+name);

        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public static GroupChat selectGroupChatByName(String groupChatName){
        GroupChat groupChat = null;
        String query = "SELECT * FROM GROUP_CHATS WHERE name=?";

        try(var connection = DriverManager.getConnection(connString, user, password);
        PreparedStatement ps = connection.prepareStatement(query)){

            ps.setString(1, groupChatName);

            ResultSet rs = ps.executeQuery();

            if(rs.next()){
                int id = rs.getInt("id");
                String name = rs.getString("name");

                groupChat = new GroupChat(id, name);
            }

        } catch (SQLException e) {
            throw new RuntimeException(e);
        }

        return groupChat;
    }

    public static boolean updateGroupChatName(int chatId, String newName){
        String query = "UPDATE GROUP_CHATS SET name=? WHERE id=?";
        try(var connection = DriverManager.getConnection(connString, user, password);
        PreparedStatement ps = connection.prepareStatement(query)){

            ps.setString(1, newName);
            ps.setInt(2, chatId);

            int rows = ps.executeUpdate();
            return rows > 0;

        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public static void createTableMessages(){
        try(var connection=DriverManager.getConnection(connString, user, password);
        var stmt = connection.createStatement()){

            String query = """
                    CREATE TABLE IF NOT EXISTS MESSAGES(
                        id SERIAL PRIMARY KEY,
                        content BYTEA NOT NULL,
                        log_timestamp BIGINT NOT NULL,
                        id_sender INTEGER NOT NULL,
                        id_group INTEGER NOT NULL,
                        FOREIGN KEY(id_sender) REFERENCES USERS(id) ON DELETE CASCADE,
                        FOREIGN KEY(id_group) REFERENCES GROUP_CHATS(id) ON DELETE CASCADE
                    );
                    """;

            stmt.executeUpdate(query);

        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public static void insertMessage(byte[] content, long timestamp, int senderId, int groupId){
        String query = """
                INSERT INTO MESSAGES(content, log_timestamp, id_sender, id_group)
                VALUES(?,?,?,?);
                """;
        try(var connection = DriverManager.getConnection(connString, user, password);
        PreparedStatement ps = connection.prepareStatement(query)){

            ps.setBytes(1, content);
            ps.setLong(2, timestamp);
            ps.setInt(3, senderId);
            ps.setInt(4, groupId);

            ps.executeUpdate();
            System.out.println("Message inserted sucessfully ");

        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public static int insertMessageReturningId(byte[] content, long timestamp, int senderId, int groupId){
        int id = -1;
        String query = """
                INSERT INTO MESSAGES(content, log_timestamp, id_sender, id_group)
                VALUES(?,?,?,?) RETURNING id;
                """;
        try(var connection = DriverManager.getConnection(connString, user, password);
            PreparedStatement ps = connection.prepareStatement(query)){

            ps.setBytes(1, content);
            ps.setLong(2, timestamp);
            ps.setInt(3, senderId);
            ps.setInt(4, groupId);

            ResultSet rs = ps.executeQuery();
            if(rs.next()){
                id = rs.getInt(1);
            }

            System.out.println("Message inserted sucessfully ");

        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return id;
    }

    public static List<Message> selectMessagesByGroup(int groupId){
        List<Message> groupMessages = new ArrayList<>();
        String query = "SELECT * FROM MESSAGES WHERE id_group=?";

        try(var connection = DriverManager.getConnection(connString, user, password);
        PreparedStatement ps = connection.prepareStatement(query)){
            ps.setInt(1,groupId);
            ResultSet rs = ps.executeQuery();

            while (rs.next()){
                int id = rs.getInt(1);
                byte[] content = rs.getBytes(2);
                long timestamp = rs.getLong(3);
                int senderId = rs.getInt(4);
                int groupIdDatabase = rs.getInt(5);

                groupMessages.add(new Message(id, content, timestamp, senderId, groupIdDatabase));
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return groupMessages;
    }

    public static boolean updateMessageById(int id, byte[] newContent){
        String query = """
                UPDATE MESSAGES SET content=? WHERE id=?;
                """;
        try(var connection = DriverManager.getConnection(connString, user, password);
        PreparedStatement ps = connection.prepareStatement(query)){

            ps.setBytes(1,newContent);
            ps.setInt(2,id);

            int rows = ps.executeUpdate();

            return rows > 0;

        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public static boolean deleteMessageById(int id){
        String query = """
                DELETE FROM MESSAGES WHERE id=?
                """;
        try(var connection = DriverManager.getConnection(connString, user, password);
        PreparedStatement ps = connection.prepareStatement(query)){

            ps.setInt(1, id);

            int rows = ps.executeUpdate();

            return rows > 0;

        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public static void createTableExtras(){
        try(var connection = DriverManager.getConnection(connString, user, password);
        var stmt = connection.createStatement()){

            String query = """
                CREATE TABLE IF NOT EXISTS EXTRAS(
                id SERIAL PRIMARY KEY,
                id_user INTEGER NOT NULL,
                public_key_dh BYTEA,
                session_key BYTEA,
                public_key_dilithium BYTEA,
                FOREIGN KEY(id_user) REFERENCES USERS(id) ON DELETE CASCADE
                );
                """;

            stmt.executeUpdate(query);

        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }
}

