<Query Kind="Program">
  <Namespace>System.IO.Compression</Namespace>
  <Namespace>System.Runtime.InteropServices</Namespace>
  <Namespace>System.Runtime.Intrinsics.Arm</Namespace>
  <Namespace>System.Security.Cryptography</Namespace>
</Query>

void Main()
{
	//IpfPackage.Unpack(@"D:\code\gaming\tree-of-savior\sample files\script_client.ipf", @"D:\code\gaming\tree-of-savior\sample files\test");
	IpfPackage.Unpack(@"D:\code\gaming\tree-of-savior\sample files\_altarget-⛄-v1.2.0.ipf", @"D:\code\gaming\tree-of-savior\sample files\test");
	IpfPackage.Repack(@"D:\code\gaming\tree-of-savior\_nearbyplayerinfo-📖-xy312.ipf", @"D:\code\gaming\tree-of-savior\extract\");
}


// file structure: https://github.com/r1emu/IPFUnpacker
// c# impl reference: https://github.com/exectails/IPFBrowser
// c# impl reference 2: IPF Suite (ILSpy'd)

public class IpfPackage
{
	private const string Password = "ofO1a0ueXA? [\xFFs h %?";
	private static readonly string[] UncompressedFileTypes = ".mp3,.fsb,.jpg".Split(',');

	public static void Unpack(string ipfPath, string outputDirectory)
	{
		using var stream = new FileStream(ipfPath, FileMode.Open, FileAccess.Read, FileShare.Read);
		using var reader = new BinaryReader(stream);

		reader.BaseStream.Position = reader.BaseStream.Length - Marshal.SizeOf<IpfFooter>();
		var footer = reader.ReadRaw<IpfFooter>().Dump("footer", 0);
		if (!footer.CheckMagicValue())
			throw new FileFormatException($"Invalid magic value: {footer.Magic:X8}");

		reader.BaseStream.Position = footer.FileTableOffset;
		var entries = Enumerable.Range(0, footer.FileCount)
			.Select(x => reader.ReadCustom<IpfFileEntry>())
			.ToArray()
			.Dump("entries", 0);

		foreach (var entry in entries)
		{
			Util.Metatext($"extracting {entry.ArchiveName}>{entry.FileName} (offset: {entry.DataOffset})").Dump();
			reader.BaseStream.Position = entry.DataOffset;

			var data = reader.ReadBytes((int)entry.CompressedLength);

			if (!UncompressedFileTypes.Any(x => entry.FileName.EndsWith(x, StringComparison.InvariantCultureIgnoreCase)))
			{
				if (footer.Revision > 11000 || footer.Revision == 0)
				{
					var encryptor = new PkwareTraditionalEncryptionData(Password);
					data = encryptor.Decrypt(data, data.Length);
				}

				using (var msOut = new MemoryStream())
				using (var msIn = new MemoryStream(data))
				using (var deflate = new DeflateStream(msIn, CompressionMode.Decompress))
				{
					deflate.CopyTo(msOut);
					data = msOut.ToArray();
				}
			}

			var path = Path.Combine(outputDirectory, entry.ArchiveName, entry.FileName);
			Directory.CreateDirectory(Path.GetDirectoryName(path));

			File.WriteAllBytes(path, data);
		}
	}
	public static void Repack(string ipfPath, string sourceDirectory, bool encrypt = true)
	{
		Console.WriteLine();
		
		var files =
		(
			from archive in Directory.GetDirectories(sourceDirectory)
			from file in Directory.GetFiles(archive, "*", SearchOption.AllDirectories).Where(x => !x.Contains(@"\.git"))
			select new
			{ 
				SourceFile = file, 
				ArchiveName = Path.GetRelativePath(sourceDirectory, archive),
				FileName = Path.GetRelativePath(archive, file),
			}
		).ToArray();
		files.Dump("files", 0);
		
		var entries = new List<IpfFileEntry>();
		var footer = new IpfFooter() with
		{
			FileCount = (ushort)files.Length,
			Magic = 101010256u,
		};
		
		using var stream = File.Create(ipfPath);
		using var writer = new BinaryWriter(stream);
		
		// write files
		foreach (var file in files)
		{
			var data = File.ReadAllBytes(file.SourceFile);
			var entry = new IpfFileEntry() with
			{
				ArchiveName = file.ArchiveName,
				Crc = Crc32.Compute(data),
				UncompressedLength = (uint)data.Length,
				FileName = file.FileName.Replace(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
				ArchiveNameLength = (ushort)file.ArchiveName.Length,
				FileNameLength = (ushort)file.FileName.Length,
				DataOffset = (uint)writer.BaseStream.Position,
			};
			
			if (!UncompressedFileTypes.Any(x => file.FileName.EndsWith(x, StringComparison.InvariantCultureIgnoreCase)))
			{
				using (var input = new MemoryStream(data))
				using (var buffer = new MemoryStream())
				using (var compress = new DeflateStream(buffer, CompressionMode.Compress))
				{
					input.CopyTo(compress);
					compress.Close();
			
					data = buffer.ToArray();
				}
					
				if (encrypt)
				{
					var pkw = new PkwareTraditionalEncryptionData(Password);
					data = pkw.Encrypt(data, data.Length);
				}
			}
			
			writer.Write(data);
			entry.CompressedLength = (uint)data.Length;
			entries.Add(entry);
		}
		entries.Dump("entries", 0);
		
		// write file table
		footer.FileTableOffset = (uint)writer.BaseStream.Position;
		foreach (var entry in entries)
		{
			writer.WriteCustom(entry);
		}
		
		// write footer
		footer.FileFooterOffset = (uint)writer.BaseStream.Position;
		writer.WriteRaw(footer.Dump());
	}
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public record struct IpfFooter(ushort FileCount, uint FileTableOffset, ushort Unknown0, uint FileFooterOffset, uint Magic, uint BaseRevision, uint Revision) :
	IBinarySerializableRaw
{
	public bool CheckMagicValue() => Magic == 0x06054B50;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public record struct IpfFileEntry(ushort FileNameLength, uint Crc, uint CompressedLength, uint UncompressedLength, uint DataOffset, ushort ArchiveNameLength) :
	IBinarySerializableRaw, IBinarySerializableCustom<IpfFileEntry>
{
	public string ArchiveName { get; set; }
	public string FileName { get; set; }

	public static IpfFileEntry Read(BinaryReader reader)
	{
		var result = reader.ReadRaw<IpfFileEntry>(fixedSize: 20);
		result.ArchiveName = reader.ReadString(result.ArchiveNameLength);
		result.FileName = reader.ReadString(result.FileNameLength);

		return result;
	}
	public void Write(BinaryWriter writer)
	{
		writer.WriteRaw(this, fixedSize: 20);
		writer.Write(ArchiveName?.ToArray() ?? throw new ArgumentNullException(nameof(ArchiveName)));
		writer.Write(FileName?.ToArray() ?? throw new ArgumentNullException(nameof(FileName)));
	}
}

public interface IBinarySerializableRaw { }
public interface IBinarySerializableCustom<T> where T : IBinarySerializableCustom<T>
{
	static abstract T Read(BinaryReader reader);
	void Write(BinaryWriter writer);
}

internal sealed class Crc32 : HashAlgorithm
{
	public const uint DefaultPolynomial = 3988292384u;

	public const uint DefaultSeed = uint.MaxValue;

	private static uint[] defaultTable;

	private readonly uint seed;

	private readonly uint[] table;

	private uint hash;

	private uint[] hash_tbl;

	public override int HashSize => 32;

	public Crc32() : this(3988292384u, uint.MaxValue)
	{
	}

	public Crc32(uint polynomial, uint seed)
	{
		table = InitializeTable(polynomial);
		hash = seed;
		this.seed = seed;
		hash_tbl = new uint[256]
		{
			0u, 1996959894u, 3993919788u, 2567524794u, 124634137u, 1886057615u, 3915621685u, 2657392035u, 249268274u, 2044508324u,
			3772115230u, 2547177864u, 162941995u, 2125561021u, 3887607047u, 2428444049u, 498536548u, 1789927666u, 4089016648u, 2227061214u,
			450548861u, 1843258603u, 4107580753u, 2211677639u, 325883990u, 1684777152u, 4251122042u, 2321926636u, 335633487u, 1661365465u,
			4195302755u, 2366115317u, 997073096u, 1281953886u, 3579855332u, 2724688242u, 1006888145u, 1258607687u, 3524101629u, 2768942443u,
			901097722u, 1119000684u, 3686517206u, 2898065728u, 853044451u, 1172266101u, 3705015759u, 2882616665u, 651767980u, 1373503546u,
			3369554304u, 3218104598u, 565507253u, 1454621731u, 3485111705u, 3099436303u, 671266974u, 1594198024u, 3322730930u, 2970347812u,
			795835527u, 1483230225u, 3244367275u, 3060149565u, 1994146192u, 31158534u, 2563907772u, 4023717930u, 1907459465u, 112637215u,
			2680153253u, 3904427059u, 2013776290u, 251722036u, 2517215374u, 3775830040u, 2137656763u, 141376813u, 2439277719u, 3865271297u,
			1802195444u, 476864866u, 2238001368u, 4066508878u, 1812370925u, 453092731u, 2181625025u, 4111451223u, 1706088902u, 314042704u,
			2344532202u, 4240017532u, 1658658271u, 366619977u, 2362670323u, 4224994405u, 1303535960u, 984961486u, 2747007092u, 3569037538u,
			1256170817u, 1037604311u, 2765210733u, 3554079995u, 1131014506u, 879679996u, 2909243462u, 3663771856u, 1141124467u, 855842277u,
			2852801631u, 3708648649u, 1342533948u, 654459306u, 3188396048u, 3373015174u, 1466479909u, 544179635u, 3110523913u, 3462522015u,
			1591671054u, 702138776u, 2966460450u, 3352799412u, 1504918807u, 783551873u, 3082640443u, 3233442989u, 3988292384u, 2596254646u,
			62317068u, 1957810842u, 3939845945u, 2647816111u, 81470997u, 1943803523u, 3814918930u, 2489596804u, 225274430u, 2053790376u,
			3826175755u, 2466906013u, 167816743u, 2097651377u, 4027552580u, 2265490386u, 503444072u, 1762050814u, 4150417245u, 2154129355u,
			426522225u, 1852507879u, 4275313526u, 2312317920u, 282753626u, 1742555852u, 4189708143u, 2394877945u, 397917763u, 1622183637u,
			3604390888u, 2714866558u, 953729732u, 1340076626u, 3518719985u, 2797360999u, 1068828381u, 1219638859u, 3624741850u, 2936675148u,
			906185462u, 1090812512u, 3747672003u, 2825379669u, 829329135u, 1181335161u, 3412177804u, 3160834842u, 628085408u, 1382605366u,
			3423369109u, 3138078467u, 570562233u, 1426400815u, 3317316542u, 2998733608u, 733239954u, 1555261956u, 3268935591u, 3050360625u,
			752459403u, 1541320221u, 2607071920u, 3965973030u, 1969922972u, 40735498u, 2617837225u, 3943577151u, 1913087877u, 83908371u,
			2512341634u, 3803740692u, 2075208622u, 213261112u, 2463272603u, 3855990285u, 2094854071u, 198958881u, 2262029012u, 4057260610u,
			1759359992u, 534414190u, 2176718541u, 4139329115u, 1873836001u, 414664567u, 2282248934u, 4279200368u, 1711684554u, 285281116u,
			2405801727u, 4167216745u, 1634467795u, 376229701u, 2685067896u, 3608007406u, 1308918612u, 956543938u, 2808555105u, 3495958263u,
			1231636301u, 1047427035u, 2932959818u, 3654703836u, 1088359270u, 936918000u, 2847714899u, 3736837829u, 1202900863u, 817233897u,
			3183342108u, 3401237130u, 1404277552u, 615818150u, 3134207493u, 3453421203u, 1423857449u, 601450431u, 3009837614u, 3294710456u,
			1567103746u, 711928724u, 3020668471u, 3272380065u, 1510334235u, 755167117u
		};
	}

	public uint compute_crc32(uint crc, char b)
	{
		return hash_tbl[(crc ^ b) & 0xFF] ^ (crc >> 8);
	}

	public override void Initialize()
	{
		hash = seed;
	}

	protected override void HashCore(byte[] buffer, int start, int length)
	{
		hash = CalculateHash(table, hash, buffer, start, length);
	}

	protected override byte[] HashFinal()
	{
		return HashValue = UInt32ToBigEndianBytes(~hash);
	}

	public static uint Compute(byte[] buffer)
	{
		return Compute(uint.MaxValue, buffer);
	}

	public static uint Compute(uint seed, byte[] buffer)
	{
		return Compute(3988292384u, seed, buffer);
	}

	public static uint Compute(uint polynomial, uint seed, byte[] buffer)
	{
		return ~CalculateHash(InitializeTable(polynomial), seed, buffer, 0, buffer.Length);
	}

	private static uint[] InitializeTable(uint polynomial)
	{
		if (polynomial == 3988292384u && defaultTable != null)
		{
			return defaultTable;
		}
		uint[] array = new uint[256];
		for (int i = 0; i < 256; i++)
		{
			uint num = (uint)i;
			for (int j = 0; j < 8; j++)
			{
				num = (((num & 1) != 1) ? (num >> 1) : ((num >> 1) ^ polynomial));
			}
			array[i] = num;
		}
		if (polynomial == 3988292384u)
		{
			defaultTable = array;
		}
		return array;
	}

	private static uint CalculateHash(uint[] table, uint seed, IList<byte> buffer, int start, int size)
	{
		uint num = seed;
		for (int i = start; i < size - start; i++)
		{
			num = (num >> 8) ^ table[(uint)(UIntPtr)(buffer[i] ^ (num & 0xFFu))];
		}
		return num;
	}

	private static byte[] UInt32ToBigEndianBytes(uint uint32)
	{
		byte[] bytes = BitConverter.GetBytes(uint32);
		if (BitConverter.IsLittleEndian)
		{
			Array.Reverse(bytes);
		}
		return bytes;
	}
}
internal class PkwareTraditionalEncryptionData
{
	//private static readonly CRC32 CRC32 = new();
	private readonly uint[] _keys = { 0x12345678, 0x23456789, 0x34567890 };
	private static readonly uint[] Crc32Matrix = new uint[]
	{
		0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
   		0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
		0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
		0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
		0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
		0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
		0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
		0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
		0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
		0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
		0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
		0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
		0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
		0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
		0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
		0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
		0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
		0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
		0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
		0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
		0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
		0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
		0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
		0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
		0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
		0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
		0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
		0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
		0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
		0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
		0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
		0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D,
	};

	public PkwareTraditionalEncryptionData(string password)
	{
		Initialize(password);
	}

	private byte MagicByte
	{
		get
		{
			var t = (ushort)((ushort)(_keys[2] & 0xFFFF) | 2);
			return (byte)((t * (t ^ 1)) >> 8);
		}
	}

	public byte[] Decrypt(byte[] cipherText, int length)
	{
		if (length > cipherText.Length)
		{
			throw new ArgumentOutOfRangeException(
				nameof(length),
				"Bad length during Decryption: the length parameter must be smaller than or equal to the size of the destination array."
			);
		}

		var plainText = new byte[length];
		//for (var i = 0; i < length; i++)
		//{
		//    var c = (byte)(cipherText[i] ^ MagicByte);
		//    UpdateKeys(c);
		//    plainText[i] = c;
		//}
		for (int i = 0; i < length; i++)
		{
			if ((i % 2) != 0)
			{
				plainText[i] = cipherText[i];
			}
			else
			{
				var c = (byte)(cipherText[i] ^ MagicByte);
				UpdateKeys(c);
				plainText[i] = c;
			}
		}
		return plainText;
	}

	public byte[] Encrypt(byte[] plainText, int length)
	{
		if (plainText is null)
		{
			throw new ArgumentNullException(nameof(plainText));
		}

		if (length > plainText.Length)
		{
			throw new ArgumentOutOfRangeException(
				nameof(length),
				"Bad length during Encryption: The length parameter must be smaller than or equal to the size of the destination array."
			);
		}

		var cipherText = new byte[length];
		for (var i = 0; i < length; i++)
		{
			//var c = plainText[i];
			//cipherText[i] = (byte)(plainText[i] ^ MagicByte);
			//UpdateKeys(c);
			if ((i % 2) != 0)
			{
				cipherText[i] = plainText[i];
			}
			else
			{
				var c = plainText[i];
				cipherText[i] = (byte)(plainText[i] ^ MagicByte);
				UpdateKeys(c);
			}
		}
		return cipherText;
	}

	private void Initialize(string password)
	{
		//        var array = StringToByteArray(password).Dump();
		//        for (var i = 0; i < password.Length; i++)
		//        {
		//            UpdateKeys(array[i]);
		//        }
		foreach (var p in password)
			UpdateKeys((byte)p);
	}

	private void UpdateKeys(byte byteValue)
	{
		_keys[0] = (uint)ComputeCrc32(_keys[0], byteValue);
		_keys[1] = _keys[1] + (byte)_keys[0];
		_keys[1] = (_keys[1] * 0x08088405) + 1;
		_keys[2] = (uint)ComputeCrc32(_keys[2], (byte)(_keys[1] >> 24));
	}

	private uint ComputeCrc32(uint W, byte B)
	{
		return Crc32Matrix[(W ^ B) & 0xFF] ^ (W >> 8);
	}
}


public static class BinaryReaderExtensions
{
	public static T ReadRaw<T>(this BinaryReader reader) where T : struct, IBinarySerializableRaw
	{
		var buffer = reader.ReadBytes(Marshal.SizeOf(typeof(T)));

		var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
		var result = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
		handle.Free();

		return result;
	}
	public static T ReadRaw<T>(this BinaryReader reader, int fixedSize) where T : struct, IBinarySerializableRaw
	{
		var buffer = new byte[Marshal.SizeOf<T>()];
		reader.ReadBytes(fixedSize).CopyTo(buffer, 0);

		var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
		var result = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
		handle.Free();

		return result;
	}
	public static T ReadCustom<T>(this BinaryReader reader) where T : IBinarySerializableCustom<T>
	{
		return T.Read(reader);
	}
	
	public static void WriteRaw<T>(this BinaryWriter writer, T data) where T : IBinarySerializableRaw
	{
		var result = new byte[Marshal.SizeOf(typeof(T))];
		
		var handle = GCHandle.Alloc(result, GCHandleType.Pinned);
		Marshal.StructureToPtr(data, handle.AddrOfPinnedObject(), fDeleteOld: false);
		handle.Free();
		
		writer.Write(result);
	}
	public static void WriteRaw<T>(this BinaryWriter writer, T data, int fixedSize) where T : IBinarySerializableRaw
	{
		var result = new byte[Marshal.SizeOf(typeof(T))];
		
		var handle = GCHandle.Alloc(result, GCHandleType.Pinned);
		Marshal.StructureToPtr(data, handle.AddrOfPinnedObject(), fDeleteOld: false);
		handle.Free();
		
		writer.Write(result, 0, fixedSize);
	}
	public static void WriteCustom<T>(this BinaryWriter writer, T data) where T : IBinarySerializableCustom<T>
	{
		data.Write(writer);
	}

	public static string ReadString(this BinaryReader reader, int length)
	{
		return new string(reader.ReadChars(length));
	}
}