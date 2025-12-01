namespace LibTSforge.PhysicalStore
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using Crypto;

    public class VistaBlock
    {
        public BlockType Type;
        public uint Flags;
        public byte[] Value;
        public string ValueAsStr
        {
            get
            {
                return Utils.DecodeString(Value);
            }
            set
            {
                Value = Utils.EncodeString(value);
            }
        }
        public uint ValueAsInt
        {
            get
            {
                return BitConverter.ToUInt32(Value, 0);
            }
            set
            {
                Value = BitConverter.GetBytes(value);
            }
        }
        public byte[] Data;
        public string DataAsStr
        {
            get
            {
                return Utils.DecodeString(Data);
            }
            set
            {
                Data = Utils.EncodeString(value);
            }
        }
        public uint DataAsInt
        {
            get
            {
                return BitConverter.ToUInt32(Data, 0);
            }
            set
            {
                Data = BitConverter.GetBytes(value);
            }
        }

        internal void Encode(BinaryWriter writer)
        {
            writer.Write((uint)Type);
            writer.Write(Flags);
            writer.Write(Value.Length);
            writer.Write(Data.Length);
            writer.Write(Value);
            writer.Write(Data);
        }

        internal static VistaBlock Decode(BinaryReader reader)
        {
            uint type = reader.ReadUInt32();
            uint flags = reader.ReadUInt32();

            int valueLen = reader.ReadInt32();
            int dataLen = reader.ReadInt32();

            byte[] value = reader.ReadBytes(valueLen);
            byte[] data = reader.ReadBytes(dataLen);
            return new VistaBlock
            {
                Type = (BlockType)type,
                Flags = flags,
                Value = value,
                Data = data,
            };
        }
    }

    public sealed class PhysicalStoreVista : IPhysicalStore
    {
        private byte[] PreHeaderBytes = { };
        private readonly List<VistaBlock> Blocks = new List<VistaBlock>();
        private readonly FileStream TSPrimary;
        private readonly FileStream TSSecondary;
        private readonly bool Production;
        private readonly PSVersion version = PSVersion.Vista;

        public byte[] Serialize()
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            writer.Write(PreHeaderBytes);

            foreach (VistaBlock block in Blocks)
            {
                block.Encode(writer);
                writer.Align(4);
            }

            return writer.GetBytes();
        }

        public void Deserialize(byte[] data)
        {
            int len = data.Length;

            BinaryReader reader = new BinaryReader(new MemoryStream(data));
            PreHeaderBytes = reader.ReadBytes(8);

            while (reader.BaseStream.Position < len - 0x14)
            {
                Blocks.Add(VistaBlock.Decode(reader));
                reader.Align(4);
            }
        }

        public void AddBlock(PSBlock block)
        {
            Blocks.Add(new VistaBlock
            {
                Type = block.Type,
                Flags = block.Flags,
                Value = block.Value,
                Data = block.Data
            });
        }

        public void AddBlocks(IEnumerable<PSBlock> blocks)
        {
            foreach (PSBlock block in blocks)
            {
                AddBlock(block);
            }
        }

        public PSBlock GetBlock(string key, string value)
        {
            foreach (VistaBlock block in Blocks)
            {
                if (block.ValueAsStr == value)
                {
                    return new PSBlock
                    {
                        Type = block.Type,
                        Flags = block.Flags,
                        Key = new byte[0],
                        Value = block.Value,
                        Data = block.Data
                    };
                }
            }

            return null;
        }

        public PSBlock GetBlock(string key, uint value)
        {
            foreach (VistaBlock block in Blocks)
            {
                if (block.ValueAsInt == value)
                {
                    return new PSBlock
                    {
                        Type = block.Type,
                        Flags = block.Flags,
                        Key = new byte[0],
                        Value = block.Value,
                        Data = block.Data
                    };
                }
            }

            return null;
        }

        public void SetBlock(string key, string value, byte[] data)
        {
            for (int i = 0; i < Blocks.Count; i++)
            {
                VistaBlock block = Blocks[i];

                if (block.ValueAsStr == value)
                {
                    block.Data = data;
                    Blocks[i] = block;
                    break;
                }
            }
        }

        public void SetBlock(string key, uint value, byte[] data)
        {
            for (int i = 0; i < Blocks.Count; i++)
            {
                VistaBlock block = Blocks[i];

                if (block.ValueAsInt == value)
                {
                    block.Data = data;
                    Blocks[i] = block;
                    break;
                }
            }
        }

        public void SetBlock(string key, string value, string data)
        {
            SetBlock(key, value, Utils.EncodeString(data));
        }

        public void SetBlock(string key, string value, uint data)
        {
            SetBlock(key, value, BitConverter.GetBytes(data));
        }

        public void SetBlock(string key, uint value, string data)
        {
            SetBlock(key, value, Utils.EncodeString(data));
        }

        public void SetBlock(string key, uint value, uint data)
        {
            SetBlock(key, value, BitConverter.GetBytes(data));
        }

        public void DeleteBlock(string key, string value)
        {
            foreach (VistaBlock block in Blocks)
            {
                if (block.ValueAsStr == value)
                {
                    Blocks.Remove(block);
                    return;
                }
            }
        }

        public void DeleteBlock(string key, uint value)
        {
            foreach (VistaBlock block in Blocks)
            {
                if (block.ValueAsInt == value)
                {
                    Blocks.Remove(block);
                    return;
                }
            }
        }

        public PhysicalStoreVista(string primaryPath, bool production)
        {
            if (version == PSVersion.Vista || version == PSVersion.Win6469) {
            TSPrimary = File.Open(primaryPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            TSSecondary = File.Open(primaryPath.Replace("-0.", "-1."), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            Production = production;
            
            Deserialize(PhysStoreCrypto.DecryptPhysicalStore(TSPrimary.ReadAllBytes(), production, PSVersion.Vista));
            TSPrimary.Seek(0, SeekOrigin.Begin);
            }
        }

        public void Dispose()
        {
            if (TSPrimary.CanWrite && TSSecondary.CanWrite)
            {
                if (version == PSVersion.Vista || version == PSVersion.Win6469) {
                byte[] data = PhysStoreCrypto.EncryptPhysicalStore(Serialize(), Production, PSVersion.Vista);

                TSPrimary.SetLength(data.LongLength);
                TSSecondary.SetLength(data.LongLength);

                TSPrimary.Seek(0, SeekOrigin.Begin);
                TSSecondary.Seek(0, SeekOrigin.Begin);

                TSPrimary.WriteAllBytes(data);
                TSSecondary.WriteAllBytes(data);

                TSPrimary.Close();
                TSSecondary.Close();
                }
            }
        }

        public byte[] ReadRaw()
        {
            byte[] data = null;
            if (version == PSVersion.Vista || version == PSVersion.Win6469) {
            data = PhysStoreCrypto.DecryptPhysicalStore(TSPrimary.ReadAllBytes(), Production, PSVersion.Vista);
            }
            TSPrimary.Seek(0, SeekOrigin.Begin);
            return data;
        }

        public void WriteRaw(byte[] data)
        {
            if (version == PSVersion.Vista || version == PSVersion.Win6469) {
            byte[] encrData = PhysStoreCrypto.EncryptPhysicalStore(data, Production, PSVersion.Vista);

            TSPrimary.SetLength(encrData.LongLength);
            TSSecondary.SetLength(encrData.LongLength);

            TSPrimary.Seek(0, SeekOrigin.Begin);
            TSSecondary.Seek(0, SeekOrigin.Begin);

            TSPrimary.WriteAllBytes(encrData);
            TSSecondary.WriteAllBytes(encrData);

            TSPrimary.Close();
            TSSecondary.Close();
            }
        }

        public IEnumerable<PSBlock> FindBlocks(string valueSearch)
        {
            List<PSBlock> results = new List<PSBlock>();

            foreach (VistaBlock block in Blocks)
            {
                if (block.ValueAsStr.Contains(valueSearch))
                {
                    results.Add(new PSBlock
                    {
                        Type = block.Type,
                        Flags = block.Flags,
                        Key = new byte[0],
                        Value = block.Value,
                        Data = block.Data
                    });
                }
            }

            return results;
        }

        public IEnumerable<PSBlock> FindBlocks(uint valueSearch)
        {
            List<PSBlock> results = new List<PSBlock>();

            foreach (VistaBlock block in Blocks)
            {
                if (block.ValueAsInt == valueSearch)
                {
                    results.Add(new PSBlock
                    {
                        Type = block.Type,
                        Flags = block.Flags,
                        Key = new byte[0],
                        Value = block.Value,
                        Data = block.Data
                    });
                }
            }

            return results;
        }
    }
}
