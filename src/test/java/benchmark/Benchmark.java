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
import org.apache.milagro.amcl.BLS461.*;
import org.apache.milagro.amcl.AES;
import client.DPASEClient;
import client.interfaces.UserClient;
import org.apache.milagro.amcl.RAND;
import server.DPASESP;
import server.interfaces.DPASEDatabase;
import server.interfaces.Storage;
import server.storage.InMemoryDPASEDatabase;


public class Benchmark {


    private static final int ITERATIONS = 50;
    private static final int WARMUP = 50;

    private static String user = "username";
    private static String password = "password";
    private static UserClient client;


    public static void main(String[] args) throws Exception {
        List<DPASESP> dpasesps= new ArrayList<>();
        setup(dpasesps);

        List<Long> times;
        List<Long> servertimes;
        ArrayList<List> time_tuple0;
        ArrayList<List> time_tuple1;
        System.out.println("Executing " + ITERATIONS + " time each with " + WARMUP + " warmups");
//
        time_tuple0 = benchmarkCreateUser();
        times = time_tuple0.get(0);
        servertimes = time_tuple0.get(1);
        System.out.println("Create user average time is " + avg(times) + "ms with std " + std(times));
        System.out.println("Create user average servertime is " + avg(servertimes) + "ns with std " + std(servertimes));



        time_tuple1 = benchmarkEncDecRequest();
        times = time_tuple1.get(0);
        servertimes = time_tuple1.get(1);
        System.out.println("Authenticate + Enc/Dec average clienttime is " + avg(times) + "ms with std " + std(times));
        System.out.println("Authenticate + Enc/Dec average servertime is " + avg(servertimes) + "ms with std " + std(servertimes));
    }


    private static void setup(List<DPASESP> dpasesps) throws Exception {
        int serverCount = 10;
        long startTime = System.currentTimeMillis();
        BIG[]  serversecrets = new BIG[serverCount];
        RAND rng = new RAND();

        /* loop for server number times
        * get random secrete for each server, which is ki hold by server
        * get a instance: Storage storage = new InMemoryDPASEDatabase
        * new instance of DPASESP dp, with input storage(instance) and i(server number)
        * adding this new instance dp with i into dpasesps list*/
        for(int i=0; i< serverCount; i++) {
              serversecrets[i] = BIG.random(rng);
              Storage storage = InMemoryDPASEDatabase.getInstance();
              DPASESP dp = new DPASESP(storage,i);
              dpasesps.add(i,dp);
        }

        /*loop for server number times
        * setup the ith server
        * get the corresponding dp of i from List
        * executing the setup process with serversecrets
        * server setup is just a parameter transmit?*/
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

    private static ArrayList<List> benchmarkCreateUser() throws Exception{
        List<Long> times = new ArrayList<>(ITERATIONS);
        List<Long> servertimes = new ArrayList<>(ITERATIONS);
        ArrayList<List> time_tuple = new ArrayList<List>();
        long startTime = 0;
        long endTime = 0;
        long serverTime = 0;
        for (int i = 0; i < ITERATIONS + WARMUP; i++) {
            startTime = java.lang.System.currentTimeMillis();
//            System.out.println(user+i);
            serverTime = client.createUserAccount(user+i, password);
            endTime = java.lang.System.currentTimeMillis();
            Thread.sleep(20);
            if(i >= WARMUP){
                times.add(endTime - startTime);
                servertimes.add(serverTime);
            }
        }
        time_tuple.add(times);
        time_tuple.add(servertimes);
        return time_tuple;
    }

    private static ArrayList<List> benchmarkEncDecRequest() throws Exception{
        List<Long> clienttimes = new ArrayList<>(ITERATIONS);
        List<Long> servertimes = new ArrayList<>(ITERATIONS);
        ArrayList<List> time_tuple = new ArrayList<List>();
        long startTime = 0;
        long endTime = 0;
        long serverTime = 0;
        for (int i = 0; i < ITERATIONS + WARMUP; i++) {
            startTime = java.lang.System.currentTimeMillis();
            serverTime = client.EncDecRequest(user+i, password);
            endTime = java.lang.System.currentTimeMillis();
            Thread.sleep(20);
            if(i >= WARMUP){
                clienttimes.add(endTime - startTime - serverTime);
                servertimes.add(serverTime);
            }
        }
        time_tuple.add(clienttimes);
        time_tuple.add(servertimes);
        return time_tuple;
    }
}