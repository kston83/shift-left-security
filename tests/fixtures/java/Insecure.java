package demo;

import java.io.IOException;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.crypto.Cipher;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilderFactory;

// Intentionally vulnerable test data for slsec-sast. Do not use.
public class Insecure extends HttpServlet {
    private Connection conn;

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");

        // SQL injection
        Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        ResultSet rs = stmt.executeQuery(sql);

        // Command injection
        String host = request.getParameter("host");
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", "ping " + host);
        pb.start();

        // Reflected XSS
        response.getWriter().write(name);

        // Path traversal
        java.io.File f = new java.io.File("/var/data/" + request.getParameter("file"));
        new java.io.FileInputStream(f);
    }

    static void weakCrypto() throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        Cipher des = Cipher.getInstance("DES/ECB/PKCS5Padding");
        Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
    }

    static void xxe() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.newDocumentBuilder();
    }
}
