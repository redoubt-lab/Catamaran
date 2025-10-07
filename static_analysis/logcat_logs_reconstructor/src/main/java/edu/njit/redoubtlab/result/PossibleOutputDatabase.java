package edu.njit.redoubtlab.result;

import java.nio.file.Paths;
import java.sql.*;

public class PossibleOutputDatabase {

    String rootDir = Paths.get("").toAbsolutePath().toString();
    String dbPath = Paths.get(rootDir, "possible_output.db").toString();

    public PossibleOutputDatabase() {
        createTable();
    }

    private Connection connect() {
        Connection conn = null;
        try {
            String url = "jdbc:sqlite:" + dbPath;
            conn = DriverManager.getConnection(url);
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
        return conn;
    }

    public void deleteByApk(String apk) {
        String sql = "DELETE FROM possible_output WHERE apk = ?";

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, apk);
            int rowsDeleted = pstmt.executeUpdate();
            System.out.println(rowsDeleted + " row(s) deleted for apk: " + apk);

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    public void createTable() {
        String sql = "CREATE TABLE IF NOT EXISTS possible_output (\n"
                + "	id integer PRIMARY KEY,\n"
                + "	apk text NOT NULL,\n"
                + "	caller text NOT NULL,\n"
                + "	content text\n"
                + ");";

        try (Connection conn = this.connect();
             Statement stmt = conn.createStatement()) {

            stmt.execute(sql);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    public void insert(String apk, String caller, String content) {
        String selectSql = "SELECT COUNT(*) FROM possible_output WHERE apk = ? AND caller = ? AND content = ?";
        String insertSql = "INSERT INTO possible_output(apk, caller, content) VALUES(?, ?, ?)";

        try (Connection conn = this.connect();
             PreparedStatement selectStmt = conn.prepareStatement(selectSql);
             PreparedStatement insertStmt = conn.prepareStatement(insertSql)) {

            selectStmt.setString(1, apk);
            selectStmt.setString(2, caller);
            selectStmt.setString(3, content);
            ResultSet rs = selectStmt.executeQuery();

            if (rs.next() && rs.getInt(1) > 0) {
                return;
            }

            insertStmt.setString(1, apk);
            insertStmt.setString(2, caller);
            insertStmt.setString(3, content);
            insertStmt.executeUpdate();

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println(e.getMessage());
        }
    }

    public void selectAll() {
        String sql = "SELECT id, apk, caller, content FROM possible_output";

        try (Connection conn = this.connect();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                System.out.println(rs.getInt("id") + "\t" +
                        rs.getString("apk") + "\t" +
                        rs.getString("caller") + "\t" +
                        rs.getString("content"));
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

}
