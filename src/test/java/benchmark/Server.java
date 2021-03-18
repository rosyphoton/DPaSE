package benchmark;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

public class Server {
    public static void main(String[] args) throws IOException{
        System.out.println("service start, waiting for connection");
        ServerSocket ss = new ServerSocket(8888);
        Socket server = ss.accept();
        InputStream is = server.getInputStream();

        byte b[] = new byte[1024];
        int len = is.read(b);
        String msg = new String(b, 0, len);
        System.out.println(msg);

        OutputStream out = server.getOutputStream();
        out.write("I got it".getBytes(StandardCharsets.UTF_8));

        out.close();
        is.close();
        server.close();
    }
}
