﻿using System.Collections.Generic;
using System.IO;
using System.IO.Compression;

using ProtoBuf;
using SteamKit2;

namespace DepotDownloader
{
    [ProtoContract]
    internal class ProtoManifest
    {
        // Proto ctor
        private ProtoManifest()
        {
            Files = new List<FileData>();
        }

        public ProtoManifest(DepotManifest sourceManifest, ulong id) : this()
        {
            sourceManifest.Files.ForEach(f => Files.Add(new FileData(f)));
            ID = id;
        }

        [ProtoContract]
        public class FileData
        {
            // Proto ctor
            private FileData()
            {
                Chunks = new List<ChunkData>();
            }

            public FileData(DepotManifest.FileData sourceData) : this()
            {
                FileName = sourceData.FileName;
                sourceData.Chunks.ForEach(c => Chunks.Add(new ChunkData(c)));
                Flags = sourceData.Flags;
                TotalSize = sourceData.TotalSize;
                FileHash = sourceData.FileHash;
            }

            [ProtoMember(1)]
            public string FileName { get; internal set; }

            /// <summary>
            /// Gets the chunks that this file is composed of.
            /// </summary>
            [ProtoMember(2)]
            public List<ChunkData> Chunks { get; }

            /// <summary>
            /// Gets the file flags
            /// </summary>
            [ProtoMember(3)]
            public EDepotFileFlag Flags { get; }

            /// <summary>
            /// Gets the total size of this file.
            /// </summary>
            [ProtoMember(4)]
            public ulong TotalSize { get; }

            /// <summary>
            /// Gets the hash of this file.
            /// </summary>
            [ProtoMember(5)]
            public byte[] FileHash { get; }
        }

        [ProtoContract(SkipConstructor = true)]
        public class ChunkData
        {
            public ChunkData(DepotManifest.ChunkData sourceChunk)
            {
                ChunkID = sourceChunk.ChunkID;
                Checksum = sourceChunk.Checksum;
                Offset = sourceChunk.Offset;
                CompressedLength = sourceChunk.CompressedLength;
                UncompressedLength = sourceChunk.UncompressedLength;
            }

            /// <summary>
            /// Gets the SHA-1 hash chunk id.
            /// </summary>
            [ProtoMember(1)]
            public byte[] ChunkID { get; }

            /// <summary>
            /// Gets the expected Adler32 checksum of this chunk.
            /// </summary>
            [ProtoMember(2)]
            public byte[] Checksum { get; }

            /// <summary>
            /// Gets the chunk offset.
            /// </summary>
            [ProtoMember(3)]
            public ulong Offset { get; }

            /// <summary>
            /// Gets the compressed length of this chunk.
            /// </summary>
            [ProtoMember(4)]
            public uint CompressedLength { get; }

            /// <summary>
            /// Gets the decompressed length of this chunk.
            /// </summary>
            [ProtoMember(5)]
            public uint UncompressedLength { get; }
        }

        [ProtoMember(1)]
        public List<FileData> Files { get; }

        [ProtoMember(2)]
        public ulong ID { get; }

        public static ProtoManifest LoadFromFile(string filename, out byte[] checksum)
        {
            if (!File.Exists(filename))
            {
                checksum = null;
                return null;
            }

            using (MemoryStream ms = new MemoryStream())
            {
                using (FileStream fs = File.Open(filename, FileMode.Open))
                using (DeflateStream ds = new DeflateStream(fs, CompressionMode.Decompress))
                    ds.CopyTo(ms);

                checksum = Util.SHAHash(ms.ToArray());

                ms.Seek(0, SeekOrigin.Begin);
                return Serializer.Deserialize<ProtoManifest>(ms);
            }
        }

        public void SaveToFile(string filename, out byte[] checksum)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                Serializer.Serialize(ms, this);

                checksum = Util.SHAHash(ms.ToArray());

                ms.Seek(0, SeekOrigin.Begin);

                using (FileStream fs = File.Open(filename, FileMode.Create))
                using (DeflateStream ds = new DeflateStream(fs, CompressionMode.Compress))
                    ms.CopyTo(ds);
            }
        }
    }
}