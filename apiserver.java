import com.pdfcrowd.*;
import java.io.*;

public class apiserver {
    private static String TEST_DIR = "../test_files";

    public static FileOutputStream getFile(String name) {
        try
        {
            String fname = String.format("%s/out/java_client%s", TEST_DIR, name);
            return new FileOutputStream(fname + ".pdf");
        }
        catch(FileNotFoundException e)
        {
            System.exit(1);
        }

        return null;
    }
    
    
    public static void main(String[] args) {
        try
        {
            if (args.length != 3) {
                System.err.println("required args: username apikey apihost");
                System.exit(1);
            }
            
            Client c = new Client(args[0], args[1], args[2]);
            c.convertURI("https://storage.googleapis.com/pdfcrowd-legacy-tests/tests/webtopdfcom.html", getFile("uri"));
            c.convertHtml("test", getFile("content"));
            c.convertFile(TEST_DIR + "/in/simple.html", getFile("upload"));
        }
        catch(PdfcrowdError e)
        {
            System.err.println(e.toString());
            System.exit(1);
        }
    }
    
}

