package com.geoattend.matcher;

import com.google.gson.*;
import com.machinezoo.sourceafis.*;
import com.sun.net.httpserver.*;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.Executors;

/** Loopback-only SourceAFIS service. Camera frames and templates stay in memory. */
public final class FingerprintMatcherServer {
    private static final String TOKEN = System.getenv().getOrDefault("FINGERPRINT_MATCHER_TOKEN", "");
    private static final double MIN_SHARPNESS = Double.parseDouble(System.getenv().getOrDefault("FINGERPRINT_MIN_SHARPNESS", "8"));
    private static final double DPI = Double.parseDouble(System.getenv().getOrDefault("FINGERPRINT_CAMERA_DPI", "500"));
    private static final int MAX_BODY = 18 * 1024 * 1024;

    public static void main(String[] args) throws Exception {
        if (TOKEN.length() < 32) throw new IllegalStateException("Set FINGERPRINT_MATCHER_TOKEN to at least 32 characters.");
        int port = Integer.parseInt(System.getenv().getOrDefault("FINGERPRINT_MATCHER_PORT", "5512"));
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 32);
        server.createContext("/v1/extract", e -> handle(e, false));
        server.createContext("/v1/match", e -> handle(e, true));
        server.setExecutor(Executors.newFixedThreadPool(2));
        server.start();
        System.out.println("GeoAttend fingerprint matcher listening on 127.0.0.1:" + port);
    }

    private static void handle(HttpExchange e, boolean matching) throws IOException {
        try {
            if (!"POST".equals(e.getRequestMethod())) { reply(e,405,"{\"error\":\"POST required\"}"); return; }
            String auth=e.getRequestHeaders().getFirst("Authorization");
            if(auth==null || !MessageDigest.isEqual(("Bearer "+TOKEN).getBytes(StandardCharsets.UTF_8),auth.getBytes(StandardCharsets.UTF_8))){reply(e,401,"{\"error\":\"Unauthorized\"}");return;}
            byte[] bytes=e.getRequestBody().readNBytes(MAX_BODY+1);
            if(bytes.length>MAX_BODY){reply(e,413,"{\"error\":\"Payload too large\"}");return;}
            JsonObject input=JsonParser.parseString(new String(bytes,StandardCharsets.UTF_8)).getAsJsonObject();
            List<Frame> frames=prepare(input.getAsJsonArray("frames"));
            if(frames.size()<3){reply(e,422,"{\"error\":\"Too few sharp frames. Clean the lens, hold still, and retry.\"}");return;}
            JsonObject output=matching?match(frames,input.getAsJsonArray("templates")):extract(frames);
            reply(e,200,output.toString());
        } catch(IllegalArgumentException|IOException ex){reply(e,422,"{\"error\":\"Frames could not be processed. Retake the scan.\"}");}
        catch(Exception ex){reply(e,500,"{\"error\":\"Matcher unavailable. Ask the lecturer if this continues.\"}");}
        finally{e.close();}
    }
    private static JsonObject extract(List<Frame> frames){
        JsonArray templates=new JsonArray();
        for(Frame f:frames.stream().limit(5).toList()) templates.add(Base64.getEncoder().encodeToString(new FingerprintTemplate(new FingerprintImage(f.png,new FingerprintImageOptions().dpi(DPI))).toByteArray()));
        JsonObject out=new JsonObject();out.add("templates",templates);return out;
    }
    private static JsonObject match(List<Frame> frames,JsonArray candidates){
        double best=-1;
        for(Frame f:frames){FingerprintMatcher matcher=new FingerprintMatcher(new FingerprintTemplate(new FingerprintImage(f.png,new FingerprintImageOptions().dpi(DPI))));for(JsonElement c:candidates)best=Math.max(best,matcher.match(new FingerprintTemplate(Base64.getDecoder().decode(c.getAsString()))));}
        JsonObject out=new JsonObject();out.addProperty("score",best);return out;
    }
    private static List<Frame> prepare(JsonArray encoded) throws IOException {
        if(encoded==null||encoded.size()!=8)throw new IllegalArgumentException("Eight frames required.");
        List<Frame> out=new ArrayList<>();
        for(JsonElement item:encoded){BufferedImage src=ImageIO.read(new ByteArrayInputStream(Base64.getDecoder().decode(item.getAsString())));if(src==null||src.getWidth()<240||src.getHeight()<240)continue;BufferedImage gray=equalize(src);double sharpness=laplacian(gray);if(sharpness<MIN_SHARPNESS)continue;ByteArrayOutputStream b=new ByteArrayOutputStream();ImageIO.write(gray,"png",b);out.add(new Frame(b.toByteArray(),sharpness));}
        out.sort(Comparator.comparingDouble(Frame::sharpness).reversed());return out;
    }
    private static BufferedImage equalize(BufferedImage src){
        int w=src.getWidth(),h=src.getHeight(),total=w*h,sum=0;int[] hist=new int[256],lut=new int[256],pixels=new int[total];
        for(int y=0;y<h;y++)for(int x=0;x<w;x++){int rgb=src.getRGB(x,y),g=(int)(.299*((rgb>>16)&255)+.587*((rgb>>8)&255)+.114*(rgb&255));pixels[y*w+x]=g;hist[g]++;}
        for(int i=0;i<256;i++){sum+=hist[i];lut[i]=Math.max(0,Math.min(255,sum*255/total));}
        BufferedImage out=new BufferedImage(w,h,BufferedImage.TYPE_BYTE_GRAY);for(int y=0;y<h;y++)for(int x=0;x<w;x++)out.getRaster().setSample(x,y,0,lut[pixels[y*w+x]]);return out;
    }
    private static double laplacian(BufferedImage im){int w=im.getWidth(),h=im.getHeight(),n=(w-2)*(h-2);double sum=0,sq=0;for(int y=1;y<h-1;y++)for(int x=1;x<w-1;x++){int v=-4*im.getRaster().getSample(x,y,0)+im.getRaster().getSample(x-1,y,0)+im.getRaster().getSample(x+1,y,0)+im.getRaster().getSample(x,y-1,0)+im.getRaster().getSample(x,y+1,0);sum+=v;sq+=(double)v*v;}double mean=sum/n;return sq/n-mean*mean;}
    private static void reply(HttpExchange e,int status,String body)throws IOException{byte[] b=body.getBytes(StandardCharsets.UTF_8);e.getResponseHeaders().set("Content-Type","application/json; charset=utf-8");e.getResponseHeaders().set("Cache-Control","no-store");e.sendResponseHeaders(status,b.length);e.getResponseBody().write(b);}
    private record Frame(byte[] png,double sharpness){}
}
