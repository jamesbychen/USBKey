using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Management;
using System.Windows.Forms;
using System.IO;
using System.Security.Cryptography;

namespace USBkey
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
            USBDevice();
        }

        private void USBDevice()
        {
             ManagementObjectCollection collection;
             using (var searcher = new ManagementObjectSearcher(@"Select * From Win32_DiskDrive where InterfaceType='USB'"))
                collection = searcher.Get();

            foreach (var device in collection)
            {
                Convert.ToString(device.GetPropertyValue("DeviceID"));
                Convert.ToString(device.GetPropertyValue("PNPDeviceID"));
                Convert.ToString(device.GetPropertyValue("Caption"));
                Convert.ToString(device.GetPropertyValue("InterfaceType"));
                Convert.ToString(device.GetPropertyValue("SerialNumber"));
                Convert.ToString(device.GetPropertyValue("Size"));
                Convert.ToString(device.GetPropertyValue("TotalCylinders"));
                Convert.ToString(device.GetPropertyValue("TotalSectors"));
                Convert.ToString(device.GetPropertyValue("TotalTracks"));
                USBD.Items.Add(Convert.ToString(device.GetPropertyValue("Caption")));
            }
            collection.Dispose();

            if (USBD.Items.Count > 0) { USBD.SelectedIndex = 0; }
            else { MessageBox.Show("Нет флешек."); }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (USBD.SelectedIndex == -1)
            {
                MessageBox.Show("Не выбрана флешка."); return;
            }

            ManagementObjectCollection collection;
            using (var searcher = new ManagementObjectSearcher(@"Select * From Win32_DiskDrive where InterfaceType='USB' and Caption='" + USBD.Items[USBD.SelectedIndex].ToString().Trim() + "'"))
                collection = searcher.Get();

            
            String key = "";
            String size = "";
            foreach (var device in collection)
            {
                key += Convert.ToString(device.GetPropertyValue("Caption"));
                key += Convert.ToString(device.GetPropertyValue("InterfaceType"));
                key += Convert.ToString(device.GetPropertyValue("SerialNumber"));
                key += Convert.ToString(device.GetPropertyValue("Size"));
                key += Convert.ToString(device.GetPropertyValue("TotalCylinders"));
                key += Convert.ToString(device.GetPropertyValue("TotalSectors"));
                key += Convert.ToString(device.GetPropertyValue("TotalTracks"));
                size = Convert.ToString(device.GetPropertyValue("Size"));
            }

            if (size.Trim().Length == 0) { MessageBox.Show("Не выбрана флешка."); return; }

            collection.Dispose();
            TextWriter tw = new StreamWriter("key.key");
            String SHA256 = ComputeHash(key, new SHA256CryptoServiceProvider());

            Keccaki keccaki = new Keccaki();
            keccaki.init(256);
            Byte[] inputBytes = Encoding.UTF8.GetBytes(SHA256);
            byte[] khash = keccaki.getHash(inputBytes);

            for (int i = 0; i < 10; i++)
            {
                khash = keccaki.hash(256, inputBytes, inputBytes.Length, khash);
            }
            tw.WriteLine(BitConverter.ToString(khash).Replace("-", ""));
            tw.Close();
            MessageBox.Show("Создан");
        }

        public string ComputeHash(string input, HashAlgorithm algorithm)
        {
            Byte[] inputBytes = Encoding.UTF8.GetBytes(input);

            Byte[] hashedBytes = algorithm.ComputeHash(inputBytes);

            return BitConverter.ToString(hashedBytes).Replace("-", "");
        }

        private void button2_Click(object sender, EventArgs e)
        {
            if (USBD.SelectedIndex == -1)
            {
                MessageBox.Show("Не выбрана флешка."); return;
            }

            ManagementObjectCollection collection;
            using (var searcher = new ManagementObjectSearcher(@"Select * From Win32_DiskDrive where InterfaceType='USB' and Caption='" + USBD.Items[USBD.SelectedIndex].ToString().Trim() + "'"))
                collection = searcher.Get();

            String key = "";
            foreach (var device in collection)
            {
                key += Convert.ToString(device.GetPropertyValue("Caption"));
                key += Convert.ToString(device.GetPropertyValue("InterfaceType"));
                key += Convert.ToString(device.GetPropertyValue("SerialNumber"));
                key += Convert.ToString(device.GetPropertyValue("Size"));
                key += Convert.ToString(device.GetPropertyValue("TotalCylinders"));
                key += Convert.ToString(device.GetPropertyValue("TotalSectors"));
                key += Convert.ToString(device.GetPropertyValue("TotalTracks"));
            }
            collection.Dispose();
            System.IO.TextReader tr = new StreamReader("key.key");
            String key2 = tr.ReadLine();
            tr.Close();
            String SHA256 = ComputeHash(key, new SHA256CryptoServiceProvider());


            Keccaki keccaki = new Keccaki();
            keccaki.init(256);
            Byte[] inputBytes = Encoding.UTF8.GetBytes(SHA256);
            byte[] khash = keccaki.getHash(inputBytes);

            for (int i = 0; i < 10; i++)
            {
                khash = keccaki.hash(256, inputBytes, inputBytes.Length, khash);
            }

            if (key2.Trim() == BitConverter.ToString(khash).Replace("-", "").Trim()) { MessageBox.Show("Норм."); } else { MessageBox.Show("Не норм."); }
        }

        private void button3_Click(object sender, EventArgs e)
        {
            Keccaki keccaki = new Keccaki();
            keccaki.init(256);
            String SHA256 = ComputeHash("Инвормация1235_!01Stop", new SHA256CryptoServiceProvider());
            Byte[] inputBytes = Encoding.UTF8.GetBytes(SHA256);
            byte[] khash = keccaki.getHash(inputBytes);

            for (int i = 0; i < 9; i++)
            {
                khash = keccaki.hash(256, inputBytes, inputBytes.Length, khash);
            }


            MessageBox.Show(BitConverter.ToString(khash).Replace("-", ""));

        }

    }


    //Kessak cash iterations

    public class Keccaki {

	    ulong[] KeccakRoundConstants = {
	        0x0000000000000001L, 0x0000000000008082L, 0x800000000000808AL, 0x8000000080008000L,
	        0x000000000000808BL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
	        0x000000000000008AL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000AL,
	        0x000000008000808BL, 0x800000000000008BL, 0x8000000000008089L, 0x8000000000008003L,
	        0x8000000000008002L, 0x8000000000000080L, 0x000000000000800AL, 0x800000008000000AL,
	        0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L,
	    };

	    int[] KeccakRhoOffsets = {0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14};

	    static int nrRounds = 24;
	    static int KeccakPermutationSize = 1600;
	    static int KeccakPermutationSizeInBytes = (KeccakPermutationSize/8);
	    static int KeccakMaximumRate = 1152;
	    static int KeccakMaximumRateInBytes = (KeccakMaximumRate/8);

	    byte[] state = new byte[KeccakPermutationSizeInBytes];
	    ulong[] stateAsWords = new ulong[KeccakPermutationSize/64];
	    byte[] dataQueue = new byte[KeccakMaximumRateInBytes];
	    ulong[] B = new ulong[25];
	    ulong[] C = new ulong[5];
	    ulong[] D = new ulong[5];
	    int rate;
	    int capacity;
	    byte diversifier;
	    int hashbitlen;
	    int bitsInQueue;
	    bool squeezing;
	    int bitsAvailableForSqueezing;

	    private ulong ROL64(ulong a, int offset) {
	        return (a << offset) | (a >> -offset);
	    }


        private void Fill<T>(T[] array, int start, int end, T value)
        {
            if (array == null)
            {
                throw new ArgumentNullException("array");
            }
            if (start < 0 || start >= end)
            {
                throw new ArgumentOutOfRangeException("fromIndex");
            }
            if (end > array.Length)
            {
                throw new ArgumentOutOfRangeException("toIndex");
            }
            for (int i = start; i < end; i++)
            {
                array[i] = value;
            }
        }

	    private void fromBytesToWords() {
	        for (int i = 0, j = 0; i < (KeccakPermutationSize/64); i++, j += 8) {
	            stateAsWords[i] = ((ulong)state[j    ] & 0xFFL)
	                            | ((ulong)state[j + 1] & 0xFFL) <<  8
	                            | ((ulong)state[j + 2] & 0xFFL) << 16
	                            | ((ulong)state[j + 3] & 0xFFL) << 24
	                            | ((ulong)state[j + 4] & 0xFFL) << 32
	                            | ((ulong)state[j + 5] & 0xFFL) << 40
	                            | ((ulong)state[j + 6] & 0xFFL) << 48
	                            | ((ulong)state[j + 7] & 0xFFL) << 56;
	        }
	    }

	    private void fromWordsToBytes() {
	        for (int i = 0, j = 0; i < (KeccakPermutationSize/64); i++, j += 8) {
	            state[j    ] = (byte)(stateAsWords[i]      );
	            state[j + 1] = (byte)(stateAsWords[i] >>  8);
	            state[j + 2] = (byte)(stateAsWords[i] >> 16);
	            state[j + 3] = (byte)(stateAsWords[i] >> 24);
	            state[j + 4] = (byte)(stateAsWords[i] >> 32);
	            state[j + 5] = (byte)(stateAsWords[i] >> 40);
	            state[j + 6] = (byte)(stateAsWords[i] >> 48);
	            state[j + 7] = (byte)(stateAsWords[i] >> 56);
	        }
	    }

	    private int index(int x, int y) {
	        return (((x)%5)+5*((y)%5));
	    }

	    private void theta() {
	        for (int x=0; x<5; x++) {
	            C[x] = 0; 
	            for (int y=0; y<5; y++) 
	                C[x] ^= stateAsWords[index(x, y)];
	            D[x] = ROL64(C[x], 1);
	        }
	        for (int x=0; x<5; x++)
	            for (int y=0; y<5; y++)
	                stateAsWords[index(x, y)] ^= D[(x+1)%5] ^ C[(x+4)%5];
	    }
	    
	    private void rho() {
	        for (int x=0; x<5; x++) for (int y=0; y<5; y++)
	            stateAsWords[index(x, y)] = ROL64(stateAsWords[index(x, y)], KeccakRhoOffsets[index(x, y)]);
	    }
	    
	    private void pi() {
	        for (int x=0; x<5; x++) for (int y=0; y<5; y++)
	            B[index(x, y)] = stateAsWords[index(x, y)];
	        for (int x=0; x<5; x++) for (int y=0; y<5; y++)
	            stateAsWords[index(0*x+1*y, 2*x+3*y)] = B[index(x, y)];
	    }
	    
	    private void chi() {
	        for (int y=0; y<5; y++) { 
	            for (int x=0; x<5; x++)
	                C[x] = stateAsWords[index(x, y)] ^ ((~stateAsWords[index(x+1, y)]) & stateAsWords[index(x+2, y)]);
	            for (int x=0; x<5; x++)
	                stateAsWords[index(x, y)] = C[x];
	        }
	    }
	    
	    private void iota(int indexRound) {
	        stateAsWords[index(0, 0)] ^= KeccakRoundConstants[indexRound];
	    }

	    void KeccakPermutation() {	      
	        fromBytesToWords();
	        for (int i=0; i<nrRounds; i++) {
	            theta();
	            rho();
	            pi();
	            chi();
	            iota(i);
	        }
	        fromWordsToBytes();	      
	    }

	    private void AbsorbQueue() {
            Fill(dataQueue, bitsInQueue / 8, rate / 8, (byte)0);
	        for (int i = 0; i < rate/8; i++) {
	            state[i] ^= dataQueue[i];
	        }	     
	        KeccakPermutation();
	        bitsInQueue = 0;
	    }

	    private void KeccakPad() {
	        if ((bitsInQueue % 8) != 0) {	           
	            byte padByte = (byte)(1 << (bitsInQueue % 8));
	            dataQueue[bitsInQueue/8] |= padByte;
	            bitsInQueue += 8-(bitsInQueue % 8);
	        } else {
	            dataQueue[bitsInQueue/8] = 0x01;
	            bitsInQueue += 8;
	        }
	        if (bitsInQueue == rate) {
	            AbsorbQueue();
	        }
	        dataQueue[bitsInQueue/8] = diversifier;
	        bitsInQueue += 8;
	        if (bitsInQueue == rate) {
	            AbsorbQueue();
	        }
	        dataQueue[bitsInQueue/8] = (byte)(rate/8);
	        bitsInQueue += 8;
	        if (bitsInQueue == rate) {
	            AbsorbQueue();
	        }
	        dataQueue[bitsInQueue/8] = 0x01;
	        bitsInQueue += 8;
	        if (bitsInQueue > 0) {
	            AbsorbQueue();
	        }
	        Array.Copy(state, 0, dataQueue, 0, rate/8);
	        bitsAvailableForSqueezing = rate;
	    }

	    public int getBitRate() {
	        return rate;
	    }

	    public int getCapacity() {
	        return capacity;
	    }
	   
	    public void init(int hashbitlen) {
	        switch(hashbitlen) {
	        case 0: 
	            capacity = 576;
	            break;
	        case 224:
	            capacity = 448;
	            break;
	        case 256:
	            capacity = 512;
	            break;
	        case 384:
	            capacity = 768;
	            break;
	        case 512:
	            capacity = 1024;
	            break;
	        default:
	        	capacity = 512;
                break;
	        }
	        rate = KeccakPermutationSize - capacity;
	        diversifier = (byte)(hashbitlen/8);
	        this.hashbitlen = hashbitlen;
            Fill(state,0,state.Length, (byte)0);
            Fill(dataQueue, 0, dataQueue.Length, (byte)0);
	        bitsInQueue = 0;
	        squeezing = false;
	        bitsAvailableForSqueezing = 0;
	    }

	    public void update(byte[] data, int databitlen) {
	        if ((bitsInQueue % 8) != 0) {
	            throw new ArgumentNullException("error");
	        }
	        if (squeezing) {
	            throw new ArgumentNullException("error");
	        }
	        int k = 0;
	        while (k < databitlen) {
	            if ((bitsInQueue == 0) && (databitlen >= rate) && (k <= (databitlen-rate))) {
	                int wholeBlocks = (databitlen - k)/rate;
	                int curData = (int)(k/8);
	                for (int j=0; j<wholeBlocks; j++, curData+=rate/8) {
	                    for (int i = 0; i < rate/8; i++) {
	                        state[i] ^= data[i+curData];
	                    }	                  
	                    KeccakPermutation();	                  
	                }
	                k += wholeBlocks*rate;
	            } else {
	                int partialBlock = databitlen - k;
	                if (partialBlock+bitsInQueue > rate) {
	                    partialBlock = rate-bitsInQueue;
	                }
	                int partialByte = partialBlock%8;
	                partialBlock -= partialByte;
	                Array.Copy(data, k/8, dataQueue, bitsInQueue/8, partialBlock/8);
	                bitsInQueue += partialBlock;
	                k += partialBlock;
	                if (bitsInQueue == rate) {
	                    AbsorbQueue();
	                }
	                if (partialByte > 0) {	                   
	                    byte lastByte = (byte)((data[k/8] & 0xFF) >> (8-partialByte));
	                    dataQueue[bitsInQueue/8] = lastByte;
	                    bitsInQueue += partialByte;
	                    k += partialByte;
	                }
	            }
	        }
	    }

	    public byte[] getHash(byte[] hashval) {
	        if (!squeezing) {
	            KeccakPad();
	            squeezing = true;
	        }
	        if (hashval == null) {
	            hashval = new byte[hashbitlen/8];
	        }
	        if (hashbitlen > 0) {
                Array.Copy(dataQueue, 0, hashval, 0, hashbitlen / 8);
	        }
	        return hashval;
	    }

	    public byte[] squeeze(byte[] output, int outputLength) {
	        if (!squeezing)
	            throw new ArgumentNullException("error");
	        if (hashbitlen != 0)
	            throw new ArgumentNullException("error");
	        if ((outputLength % 8) != 0)
	            throw new ArgumentNullException("error");
	        if (output == null) {
	            output = new byte[(int)outputLength];
	        }
	        int i = 0;
	        while (i < outputLength) {
	            if (bitsAvailableForSqueezing == 0) {	              
	                KeccakPermutation();
	                if (rate != 1024) {
                        throw new ArgumentNullException("error");
	                }
                    Array.Copy(state, 0, dataQueue, 0, rate / 8);
	                bitsAvailableForSqueezing = rate;
	            }
	            int partialBlock = outputLength - i;
	            if (partialBlock > bitsAvailableForSqueezing) {
	                partialBlock = bitsAvailableForSqueezing;
	            }
                Array.Copy(dataQueue, (rate - bitsAvailableForSqueezing) / 8, output, (int)(i / 8), (int)(partialBlock / 8));
	            bitsAvailableForSqueezing -= partialBlock;
	            i += partialBlock;
	        }
	        return output;
	    }

	    public byte[] hash(int hashbitlen, byte[] data, int databitlen, byte[] hashval) {
	        init(hashbitlen);
	        update(data, databitlen);
	        hashval = getHash(hashval);
	        return hashval;
	    }

	    public byte[] duplexing(byte[] sigma, int sigmaLength, byte[] z, int zLength) {	       
	        if(8*sigmaLength > rate - 2){
                throw new ArgumentNullException("error");
	        }
	        if(8*zLength > rate){
                throw new ArgumentNullException("error");
	        }	 
	        for (int i = 0; i < sigmaLength; i++) {
	            state[i] ^= sigma[i];
	        }	  
	        state[sigmaLength] ^= 0x01;
	        state[rate/8-1] ^= 0x80;
	   
	        KeccakPermutation();
	       
	        if (z == null && zLength > 0) {
	            z = new byte[zLength];
	        }
	        for (int i = 0; i < zLength; i++) {
	            z[i] = state[i];
	        }
	        return z;
	    }

	}

}
