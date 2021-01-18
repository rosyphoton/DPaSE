/*
 * inspiration from
 * https://www.javacodegeeks.com/2016/12/adding-microbenchmarking-build-process.html
 * and
 * https://www.mkyong.com/java/java-jmh-benchmark-tutorial/
 */

package benchmark;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.*;

import client.SoftwareClientCryptoModule;
import client.interfaces.ClientCryptoModule;
import model.OPRFResponse;
import org.apache.milagro.amcl.BLS461.*;
import org.apache.milagro.amcl.AES;
import client.DPASEClient;
import client.interfaces.UserClient;
import org.apache.milagro.amcl.RAND;
import server.DPASESP;
import server.interfaces.DPASEDatabase;
import server.interfaces.Storage;
import server.storage.InMemoryDPASEDatabase;


public class BenchmarkServer {


    private static final int ITERATIONS = 5;
    private static final int WARMUP = 5;

    private static String user = "username";
    private static String password = "password";
    private static UserClient client;

    private static PublicKey uukp;
    private static DPASEDatabase database;
    private static String result;


    public static void main(String[] args) throws Exception {
        /*List<Long> times;
        System.out.println("Executing " + ITERATIONS + " time each with " + WARMUP + " warmups");
        times = benchStime();
        System.out.println("server time average time is " + avg(times) + "ms with std " + std(times));

        result = getUserrKey(user);*/


        List<DPASESP> dpasesps= new ArrayList<>();
        setup(dpasesps);

        List<Long> times;
        System.out.println("Executing " + ITERATIONS + " time each with " + WARMUP + " warmups");

        times = benchmarkCreateUser();
        System.out.println("Create user average time is " + avg(times) + "ms with std " + std(times));

        times = benchmarkEncDecRequest();
        System.out.println("Authenticate average time is " + avg(times) + "ms with std " + std(times));
    }


    private static void setup(List<DPASESP> dpasesps) throws Exception {
        int serverCount = 1;
        long startTime = System.currentTimeMillis();
        BIG[]  serversecrets = new BIG[serverCount];
        RAND rng = new RAND();

        for(int i=0; i< serverCount; i++) {
            serversecrets[i] = BIG.random(rng);
            Storage storage = InMemoryDPASEDatabase.getInstance();
            DPASESP dp = new DPASESP(storage,i);
            dpasesps.add(i,dp);
        }


        for(int i = 0; i< serverCount; i++) {
            try {
                System.out.println("setting up server "+i);
                long s1 = System.currentTimeMillis();
                DPASESP dpasesp = dpasesps.get(i);
                dpasesp.setup(serversecrets[i]);


                System.out.println("finished with server "+i+ "("+(System.currentTimeMillis()-s1)+")");
            } catch(Exception e) {
                e.printStackTrace();
                System.out.println("Failed to start IdP");
            }

        }
        client = new DPASEClient(dpasesps);
        System.out.println("setup took "+(System.currentTimeMillis()-startTime)+" ms");
    }

    private static double avg(List<Long> times) {
        double sum = 0;
        for (int i = 0; i < times.size(); i++) {
            sum += times.get(i).doubleValue();
        }
        return sum/times.size();
    }

    private static double std(List<Long> times) {
        double avg = avg(times);
        double squaredDiff = 0.0;
        double sum = 0;
        for (int i = 0; i < times.size(); i++) {
            squaredDiff += (avg - times.get(i).doubleValue()) * (avg - times.get(i).doubleValue());
        }
        return Math.sqrt(squaredDiff/times.size());
    }

    private static List<Long> benchmarkCreateUser() throws Exception{

        List<Long> times = new ArrayList<>(ITERATIONS);
        long startTime = 0;
        long endTime = 0;
        for (int i = 0; i < ITERATIONS + WARMUP; i++) {
            startTime = java.lang.System.currentTimeMillis();
            client.createUserAccount(user+i, password);
            endTime = java.lang.System.currentTimeMillis();
            Thread.sleep(20);
            if(i >= WARMUP){
                times.add(endTime - startTime);
            }
        }
        return times;
    }

    private static List<Long> benchmarkEncDecRequest() throws Exception{
        List<Long> times = new ArrayList<>(ITERATIONS);
        long startTime = 0;
        long endTime = 0;
        for (int i = 0; i < ITERATIONS + WARMUP; i++) {
            startTime = java.lang.System.currentTimeMillis();
            client.EncDecRequest(user+i, password);
            endTime = java.lang.System.currentTimeMillis();
            Thread.sleep(20);
            if(i >= WARMUP){
                times.add(endTime - startTime);
            }
        }
        return times;
    }


    private static List<Long> benchStime() throws Exception {
        List<java.lang.Long> times = new ArrayList<>(ITERATIONS);
        long startTime = 0;
        long endTime = 0;
        Storage storage = InMemoryDPASEDatabase.getInstance();
        DPASESP dp = new DPASESP(storage, 1);
        BIG  serversecret = new BIG();
        dp.setup(serversecret);

        startTime = java.lang.System.currentTimeMillis();
        Random rand;
        RAND rng = new RAND();
        BIG r = BIG.random(rng);
        ClientCryptoModule cryptoModule;
        String username = "username";
        String password = "password";

        byte[] pw = password.getBytes();
        long salt = System.currentTimeMillis();
        cryptoModule = new SoftwareClientCryptoModule(new Random(1));


        byte[] nonce = cryptoModule.constructNonce(username, salt);
        ECP2 xMark = cryptoModule.hashAndMultiply(r, pw);

        for (int i = 0; i < ITERATIONS + WARMUP; i++) {

            startTime = java.lang.System.currentTimeMillis();
            OPRFResponse response=dp.performOPRF(Arrays.toString(nonce), username, xMark, null);
            endTime = java.lang.System.currentTimeMillis();
            Thread.sleep(20);
            if (i >= WARMUP) {
                times.add(endTime - startTime);
            }
        }
        return times;
    }

    private static String getUserrKey(String username)
    {
        Storage storage = InMemoryDPASEDatabase.getInstance();
        uukp = database.getUserKey(username);
//        System.out.println(uukp.toString());
        return uukp.toString();
    }
}
