package edu.njit.redoubtlab.result;

import java.nio.file.Paths;
import java.sql.*;

public class ResultDatabase {
    private final String rootDir = Paths.get("").toAbsolutePath().toString();
    private final String dbPath = Paths.get(rootDir, "app_result.db").toString();

    public ResultDatabase() {
        try (Connection conn = this.connect()) {
            if (conn != null) {
                String createTableSQL = "CREATE TABLE IF NOT EXISTS TestResult (" +
                        "apk_name TEXT PRIMARY KEY," +
                        "finding_outputs_time TEXT NOT NULL," +
                        "graph_mem_mb TEXT NOT NULL," +
                        "is_success INTEGER NOT NULL" +
                        ");";
                try (Statement stmt = conn.createStatement()) {
                    stmt.execute(createTableSQL);
                }
            }
        } catch (SQLException e) {
            System.err.println("Error during table creation: " + e.getMessage());
        }
    }

    private Connection connect() {
        Connection conn = null;
        try {
            String url = "jdbc:sqlite:" + dbPath;
            conn = DriverManager.getConnection(url);
        } catch (SQLException e) {
            System.err.println("Connection error: " + e.getMessage());
        }
        return conn;
    }

    public void insertTestResult(TestResult result) {
        String insertSQL = "INSERT INTO TestResult(apk_name, finding_outputs_time, graph_mem_mb, is_success) " +
                "VALUES(?,?,?,?)";

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(insertSQL)) {
            pstmt.setString(1, result.getApkName());
            pstmt.setString(2, result.getFindingOutputsTime());
            pstmt.setString(3, result.getGraphMemMB());
            pstmt.setInt(4, result.isSuccess() ? 1 : 0);

            pstmt.executeUpdate();
        } catch (SQLException e) {
            if (e.getMessage().contains("UNIQUE constraint failed")) {
                System.err.println("Error: Duplicate apk_name entry. This apk_name already exists in the database.");
            } else {
                System.err.println("Insertion error: " + e.getMessage());
            }
        }
    }

    public void queryTestResults() {
        String querySQL = "SELECT * FROM TestResult";
        try (Connection conn = this.connect();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(querySQL)) {

            while (rs.next()) {
                TestResult result = new TestResult(
                        rs.getString("apk_name"),
                        rs.getString("finding_outputs_time"),
                        rs.getString("graph_mem_mb"),
                        rs.getInt("is_success") == 1
                );
                System.out.println(result);
            }
        } catch (SQLException e) {
            System.err.println("Query error: " + e.getMessage());
        }
    }

    public boolean existsApkName(String apkName) {
        String querySQL = "SELECT 1 FROM TestResult WHERE apk_name = ?";
        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(querySQL)) {
            pstmt.setString(1, apkName);
            try (ResultSet rs = pstmt.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            System.err.println("Exists check error: " + e.getMessage());
            return false;
        }
    }
}