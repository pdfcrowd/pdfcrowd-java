import com.pdfcrowd.*;
import java.io.*;

public class apitest {
    private static String TEST_DIR = "../test_files";
    
    public static FileOutputStream getFile(String name, boolean use_ssl) {
        try
        {
            String fname = String.format("%s/out/java_client%s", TEST_DIR, name);
            if (use_ssl) fname += "_ssl";
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
            if (args.length > 2)
                Client.API_HOSTNAME = args[2];
            
            if (args.length == 5) {
                Client.API_HTTP_PORT = Integer.parseInt(args[3]);
                Client.API_HTTPS_PORT = Integer.parseInt(args[4]);
            }
            
            System.out.println(String.format("using %s ports %d %d",
                                             Client.API_HOSTNAME,
                                             Client.API_HTTP_PORT,
                                             Client.API_HTTPS_PORT));
            
            String html = "<html><body>Uploaded content!</body></html>";
            Client c = new Client(args[0], args[1]);

            //c.setNoPrint();
            //c.setPageHeight(-1.0);
            c.setPageMode(Client.FULLSCREEN);

            int nloop = (0 == Client.API_HOSTNAME.compareTo("pdfcrowd.com")) ? 2 : 1;

            for(int i=0; i<nloop; i++)
            {
                boolean use_ssl = (i==0) ? false : true;
                c.useSSL(use_ssl);
                int nTokens = c.numTokens();

                c.setPageWidth(8.4*72);
                c.setPageHeight(10.9*72);
                c.setHorizontalMargin(72);
                c.setVerticalMargin(2*72);
                c.convertURI("http://www.web-to-pdf.com/", getFile("uri", use_ssl));

                c.setPageWidth("8.1in");
                c.setPageHeight("10.1in");
                c.setHorizontalMargin("2in");
                c.setVerticalMargin("1in");
                c.convertHtml(html, getFile("content", use_ssl));
                
                c.convertFile(TEST_DIR + "/in/simple.html", getFile("upload", use_ssl));
                c.convertFile(TEST_DIR + "/in/archive.tar.gz", getFile("archive", use_ssl));
                int afterTokens = c.numTokens();
                System.out.println(afterTokens);
                if (nTokens-4 != afterTokens)
                    throw new RuntimeException(
                        String.format("Got unexpected number of tokens: %d, expected %d", afterTokens, nTokens-4));

                try
                {
                    FileOutputStream fileStream;
                    fileStream = new FileOutputStream("../test_files/out/java_client_filestream.pdf");
                    c.convertHtml(html, fileStream);
                    fileStream.close();

                    ByteArrayOutputStream memStream  = new ByteArrayOutputStream();
                    c.convertHtml(html, memStream);
                    memStream.writeTo(new FileOutputStream("../test_files/out/java_client_from_bytestream.pdf"));
                }
                // catch(FileNotFoundException e)
                // {
                //     System.err.println(e.toString());                    
                //     System.exit(1);
                // }
                catch(IOException e)
                {
                    System.err.println(e.toString());
                    System.exit(1);
                }
                
            }
        }
        catch(PdfcrowdError e)
        {
            System.err.println(e.toString());
            System.exit(1);
        }
    }
    
}
