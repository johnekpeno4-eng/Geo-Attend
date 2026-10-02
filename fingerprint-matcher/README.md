# GeoAttend SourceAFIS worker

This Java 17 service is called only by the GeoAttend Node.js server. It binds to `127.0.0.1`, checks a shared bearer token, processes frames in memory, and never writes camera images to disk.

## Build and run on Windows

1. Install Java 17 and Maven.
2. From the `fingerprint-matcher` directory, build the worker:

   ```powershell
   mvn -DskipTests package
   ```

3. Set the same `FINGERPRINT_MATCHER_TOKEN` value used by GeoAttend's `.env`, then start the worker:

   ```powershell
   $env:FINGERPRINT_MATCHER_TOKEN = 'the-same-long-random-value-from-your-.env'
   java -jar target/fingerprint-matcher-1.0.0.jar
   ```

4. Start GeoAttend in a second terminal. Keep both processes running.

The camera DPI and sharpness floor are starting settings. Phone-camera imagery must be calibrated with real enrollment and check-in captures before choosing a production score threshold. A regular phone camera is not a dedicated fingerprint reader.
