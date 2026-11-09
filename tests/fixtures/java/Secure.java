package demo;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import javax.crypto.Cipher;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;

// Secure counterpart of Insecure.java: must produce no findings.
public class Secure extends HttpServlet {
    private Connection conn;

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");

        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, name);
        ps.executeQuery();

        ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", "localhost");
        pb.start();

        response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_OK);
    }

    static void strongCrypto() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update("data".getBytes(StandardCharsets.UTF_8));
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
    }

    static void safeXml() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        dbf.newDocumentBuilder();
    }
}
