package client;

import java.io.UnsupportedEncodingException;
import java.lang.Boolean;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import org.apache.milagro.amcl.AES;
import org.apache.milagro.amcl.BLS461.*;

import client.interfaces.ClientCryptoModule;
import client.interfaces.UserClient;
import model.OPRFResponse;
import model.exceptions.UserCreationFailureException;
import server.DPASESP;


public class DPASEClient implements UserClient {

    private List<? extends DPASESP> servers;
    private ClientCryptoModule cryptoModule;
    private static ByteBuffer buffer = ByteBuffer.allocate(8);

    public DPASEClient(List<? extends DPASESP> servers) {
        this.servers = servers;
        cryptoModule = new SoftwareClientCryptoModule(new Random(1));
    }

    @Override
    public long createUserAccount(String username, String password) throws UserCreationFailureException {
        try{
        byte[] pw = password.getBytes();    //get the ASCII code of the String
        long salt = System.currentTimeMillis(); //get the current time in the form of ms as salt value
        byte[] nonce = this.cryptoModule.constructNonce(username, salt); //construct a nonce given username and salt.
        BIG r = cryptoModule.getRandomNumber(); //produce a random number.
        ECP2 xMark = cryptoModule.hashAndMultiply(r, pw); // = H(pw)^r. This method is override in SCCM.java.
//        List<Long> server_times = new ArrayList<>(servers.size());
        long start_time = 0;
        long end_time = 0;
        long sum_time = 0;

        KeyPair ukp = performOPRF(username, pw, r, xMark, Arrays.toString(nonce));
//        System.out.println(ukp.getPublic());
        List<Boolean> bList = new ArrayList<>();
        Boolean b;
        int index = 0;


        for (DPASESP server : servers) {
            start_time = java.lang.System.nanoTime();
//            System.out.println(start_time);
            b = server.finishRegistration(username, ukp.getPublic(), salt); //send user's data to server. (uid, upk)
            end_time = java.lang.System.nanoTime();
//            System.out.println(end_time);
            sum_time += (end_time-start_time);
            bList.add(index, b);
            index++;
        }

        int approvedCount = 0;
        index = 0;
        for (Boolean bElement : bList) {
            bElement = bList.get(index);
            if (bElement == true)
                approvedCount++;
            index++;
        }
        if (approvedCount != servers.size()) {
            throw new UserCreationFailureException("Not all servers finished registration");
        }
        return sum_time;
    }
     catch(Exception e){
            e.printStackTrace();
            throw new UserCreationFailureException(e);
        }
    }

    private static double avg(List<Long> times) {
        double sum = 0;
        for (int i = 0; i < times.size(); i++) {
            sum += times.get(i).doubleValue();
        }
        return sum/times.size();
    }


    @Override
    public long EncDecRequest(String username, String password) {

        byte[] pw = password.getBytes();
        long salt = System.currentTimeMillis();
        byte[] nonce = this.cryptoModule.constructNonce(username, salt);    //here nonce is qid, also known as ssid
        int flag = 0;

        long start_time = 0;
        long end_time = 0;
        long sum_time = 0;

        try{
            BIG r = cryptoModule.getRandomNumber();
            ECP2 xMark = cryptoModule.hashAndMultiply(r, pw); // = H(pw)^r, com
            KeyPair ukp = performOPRF(username, pw, r, xMark, Arrays.toString(nonce));  //however, here we get (ukp', usk'), calculated with Y1

            byte[] signature = signUidAndNonce(ukp.getPrivate(), username.getBytes(), nonce);
            List<Boolean> bList = new ArrayList<>();
            Boolean b;
            int index = 0;
            for (DPASESP server: servers){
                start_time = System.currentTimeMillis();
                b = server.authenticate(username, salt, signature); //this step should verify signature, b should indicate the authentication result
                end_time = System.currentTimeMillis();
                bList.add(index, b);
                sum_time += (end_time - start_time);
                index ++;
            }
            int approvedCount = 0;
            index = 0;
            for(Boolean bElement: bList)
            {
                if(bList.get(index)==true)
                    approvedCount++;
                index ++;
            }
            if(approvedCount != servers.size()) {
                throw new UserCreationFailureException("User not authenticated");
            }

            //Enc or Dec
            //String message;
            if(flag == 0)
            {
//                String c = EncRequest(username, pw, r, xMark, Arrays.toString(nonce)); //it should start from the calculation of Y2
                long server_enctime = EncRequest(username, pw, r, xMark, Arrays.toString(nonce)); //it should start from the calculation of Y2
                sum_time += server_enctime;
//                System.out.println(c);
            }
            else
            {
//                String m = DecRequest(username, pw, r, xMark, Arrays.toString(nonce)); //same as above
                long server_dectime = DecRequest(username, pw, r, xMark, Arrays.toString(nonce)); //same as above
                sum_time += server_dectime;
//                System.out.println(m);
            }
        } catch(Exception e) {
            e.printStackTrace();
        }
//        return null;
        return sum_time;
    }

    private KeyPair performOPRF(String username, byte[] pw, BIG r, ECP2 xMark, String ssid) throws Exception {

        List<OPRFResponse> responseList = new ArrayList<>();
        int index = 0;
        int i;
        for (DPASESP server : servers) {
            responseList.add(index, server.performOPRF(ssid, username, xMark, null));   //input these data to the server side to calculate y, with a response res, which can get both ssid and y
            index ++;
        }
        List<FP12> responses = new ArrayList<>();
        for (OPRFResponse resp : responseList) {
            if (!ssid.equals(resp.getSsid())) {
                throw new UserCreationFailureException("Invalid server response");
            }
            responses.add(resp.getY()); //if ssid.equals true, add y into responses. responses is the List of yi
        }

        byte[] privateBytes = processReplies(responses, r, null, pw);
        KeyPair keys = cryptoModule.generateKeysFromBytes(privateBytes);
        return keys;
    }

    private byte[] processReplies(List<FP12> responses, BIG r, ECP com, byte[] password) {
        List<byte[]> toHash = new ArrayList<>();
        toHash.add(password);
        if (com!= null)
        {
            String temp = com.toString();
            byte[] bytes = temp.getBytes();
            toHash.add(bytes);
        }

        BIG rModInv = new BIG();
        rModInv.copy(r);
        rModInv.invmodp(new BIG(ROM.CURVE_Order));
        FP12 yMark = new FP12();
        yMark.one();
        for (FP12 current : responses) {
            FP12 receivedY = current.pow(rModInv);
            yMark.mul(receivedY);   //here yMark is y: y ← ∏j∈[n] yj^(r1^(-1))
        }
        byte[] rawBytes = new byte[12*CONFIG_BIG.MODBYTES];
        yMark.toBytes(rawBytes);
        toHash.add(rawBytes);

        return cryptoModule.hash(toHash);
    }

    private byte[] signUidAndNonce(PrivateKey privateKey, byte[] uid, byte[] nonce) throws Exception{
        List<byte[]> message = new ArrayList<byte[]>();
        message.add(nonce);
        message.add(uid);
        return cryptoModule.sign(privateKey, message);
    }

    public byte[] hashMessage(byte[] message, byte[] salt)
    {
//        long salt = System.currentTimeMillis();
//        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
//        buffer.putLong(salt);
        List<byte[]> toHash = new ArrayList<>();
        toHash.add(message);
//        toHash.add(buffer.array());
        toHash.add(salt);
        byte[] bytes = cryptoModule.hash(toHash);
        return bytes;   //here is 64 bytes after sha-512
    }

    public long EncRequest(String username, byte[] pw, BIG r, ECP2 xMark, String ssid) throws NoSuchAlgorithmException {
        byte[] block=new byte[1000];  //here block is the message to be encrypted, 16bytes, 128bits
//        long rho = System.currentTimeMillis();  //rou is the random selected parameter with length lamda. datatype is long, so 64 bits, 8bytes
        byte[] rho = new byte[32];

        int i;
        for(i=0;i<block.length;i++) block[i]= (byte)i;
        for(i=0;i<32;i++) rho[i]= (byte)i;

        int length = block.length + rho.length;
        byte[] e = new byte[length];

        long start_time = 0;
        long end_time = 0;
        long sum_time = 0;

        ECP com = cryptoModule.hashToECPElement(hashMessage(block, rho));

        List<OPRFResponse> responseList = new ArrayList<>();
        int index = 0;
        for (DPASESP server : servers) {
            start_time = System.currentTimeMillis();
            responseList.add(index, server.performOPRF(ssid, username, xMark, com));
            end_time = System.currentTimeMillis();
            sum_time += (end_time - start_time);
            index ++;
        }
        List<FP12> responses = new ArrayList<>();
        for (OPRFResponse resp : responseList) {
/*            if (!ssid.equals(resp.getSsid())) {
                throw new UserCreationFailureException("Invalid server response");
            }*/
            responses.add(resp.getY());
        }

        byte[] privateBytes = processReplies(responses, r, com, pw);    //here is Y2, which is computed with com!=null


        byte[] key=privateBytes;    //Y2, after the calculation of Y2, the next step should be changed

        byte[] semival = cryptoModule.HPRG(key, length);    //computing HPRG(Y2, |m|+lamda).
        /*System.out.println("semival len:" + semival.length);*/

        //convert rou from long to byte[]
//        byte[] rou_bytes = ByteBuffer.allocate(8).putLong(rou).array();

        byte[] m_rho = new byte[length];            //the code block below is the combination of message and rho
        for (int u = 0; u < block.length; u++)
        {
            m_rho[u] = block[u];
        }
        for (int t = block.length; t < length; t++)
        {
            m_rho[t] = rho[t-block.length];
        }

        /*System.out.println("m_rou:" + m_rou.length);*/

//        int ll = 0;
        for (int p = 0; p< length; p++)
        {
            e[p] = (byte) (semival[p] ^ m_rho[p]);      //executing XOR byte by byte
        }

        /*System.out.println("e len:" + e.length);
        System.out.println(Arrays.toString(e));*/

        String e_s = null;
        try {
            e_s = new String(e, "ISO-8859-1");
        } catch (UnsupportedEncodingException unsupportedEncodingException) {
            unsupportedEncodingException.printStackTrace();
        }

        String com_s = com.toString();

        String ciphertext_c = e_s + com_s;

//        return ciphertext_c;
        return sum_time;


        /*byte[] iv=new byte[16];

        for (i=0;i<16;i++) iv[i]=(byte)i;
        for (i=0;i<16;i++) block[i]=(byte)i;

        AES a=new AES();

        a.init(AES.CTR16,32,key,iv);


        a.encrypt(block);*/

    }

    public long DecRequest(String username, byte[] pw, BIG r, ECP2 xMark, String ssid) throws NoSuchAlgorithmException{
        int length = 48;
        byte[] message = new byte[16];
        byte[] rho = new byte[32];

        String cipher = new String();
        int i;
        for (i = 0; i < 283; i++) cipher += "a";

        String e_s = cipher.substring(0, 24);
        String com_s = cipher.substring(24, 259);

        long start_time = 0;
        long end_time = 0;
        long sum_time = 0;

        /*System.out.println(e_s);
        System.out.println(com_s);*/

        byte[] e = e_s.getBytes();

        BIG big1 = BIG.fromBytes(com_s.getBytes());
        ECP com = ECP.generator().mul(big1);


        List<OPRFResponse> responseList = new ArrayList<>();
        int index = 0;
        for (DPASESP server : servers) {
            start_time = System.currentTimeMillis();
            responseList.add(index, server.performOPRF(ssid, username, xMark, com));
            end_time = System.currentTimeMillis();
            sum_time += (end_time - start_time);
            index ++;
        }
        List<FP12> responses = new ArrayList<>();
        for (OPRFResponse resp : responseList) {
            /*if (!ssid.equals(resp.getSsid())) {
                throw new UserCreationFailureException("Invalid server response");
            }*/
            responses.add(resp.getY());
        }

        byte[] privateBytes = processReplies(responses, r, com, pw);    //here is Y2, which is computed with com!=null


        byte[] key=privateBytes;    //Y2, after the calculation of Y2, the next step should be changed

        byte[] semival = cryptoModule.HPRG(key, length);    //computing HPRG(Y2, |m|+lamda).

        byte[] mp = new byte[48];
        for (int xp = 0; xp < 48; xp++)
        {
            mp[xp] = (byte)(semival[xp] ^ e[xp]);       //XOR between HPRG and e
        }

        for (int p = 0; p< 16; p++)
        {
            message[p] = mp[p];
        }

        for (int u = 16; u < length; u++)
        {
            rho[u-16] = mp[u];
        }

        /*if (com == cryptoModule.hashToECPElement(hashMessage(message, rou_long)))
            return message.toString();
        else return null;*/
//        return message.toString();
        return sum_time;
    }

}


