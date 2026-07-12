using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace HashPeek.Services
{
    public class FileHashService
    {
        public FileHashService()
        {
        }

        /// <summary>
        /// Generate hash string from a given algorithm and text.
        /// </summary>
        /// <param name="algo"></param>
        /// <param name="text"></param>
        /// <returns></returns>
        private static string GenerateHashFromString(HashAlgorithm algo, string text)
        {
            // Compute hash from text parameter
            algo.ComputeHash(Encoding.UTF8.GetBytes(text));

            // Get has value in array of bytes
            var result = algo.Hash;

            if(result == null)
                return string.Empty;
            
            // Return as hexadecimal string
            return string.Join(
                string.Empty,
                result.Select(x => x.ToString("x2")));
        }

        /// <summary>
        /// Generate hash string from a given algorithm and stream.
        /// </summary>
        /// <param name="algo"></param>
        /// <param name="stream"></param>
        /// <returns></returns>
        private string GenerateHashFromStream(HashAlgorithm algo, Stream stream)
        {
            // Compute hash from text parameter
            algo.ComputeHash(stream);

            // Get has value in array of bytes
            var result = algo.Hash;

            if (result == null)
                return string.Empty;
            
            // Return as hexadecimal string
            return string.Join(
                string.Empty,
                result.Select(x => x.ToString("x2")));
        }

        /// <summary>
        /// Generate MD5 hash from a given file.
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns></returns>
        public string Md5(string filePath)
        {
            using var stream = File.OpenRead(filePath);
            return Md5(stream);
        }

        /// <summary>
        /// Generate MD5 hash from a given stream.
        /// </summary>
        /// <param name="stream"></param>
        /// <returns></returns>
        public string Md5(Stream stream)
        {
            var result = default(string);

            using var algo = System.Security.Cryptography.MD5.Create();
            result = GenerateHashFromStream(algo, stream);

            return result;
        }

        /// <summary>
        /// Generate SHA1 hash from a given file.
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns></returns>
        public string Sha1(string filePath)
        {
            using var stream = File.OpenRead(filePath);
            return Sha1(stream);
        }

        /// <summary>
        /// Generate SHA1 hash from a given stream.
        /// </summary>
        /// <param name="stream"></param>
        /// <returns></returns>
        public string Sha1(Stream stream)
        {
            var result = default(string);

            using var algo = System.Security.Cryptography.SHA1.Create();
            result = GenerateHashFromStream(algo, stream);

            return result;
        }

        /// <summary>
        /// Generate SHA256 hash from a given file.
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns></returns>
        public string Sha256(string filePath)
        {
            using var stream = File.OpenRead(filePath);
            return Sha256(stream);
        }

        /// <summary>
        /// Generate SHA256 hash from a given stream.
        /// </summary>
        /// <param name="stream"></param>
        /// <returns></returns>
        public string Sha256(Stream stream)
        {
            var result = default(string);

            using var algo = System.Security.Cryptography.SHA256.Create();
            result = GenerateHashFromStream(algo, stream);
            
            return result;
        }

        /// <summary>
        /// Generate SHA256 hash from a given string.
        /// </summary>
        /// <param name="text"></param>
        /// <returns></returns>
        public string Sha256String(string text)
        {
            var result = default(string);

            using var algo = System.Security.Cryptography.SHA256.Create();
            result = GenerateHashFromString(algo, text);

            return result;
        }

        /// <summary>
        /// Generate SHA512 hash from a given file.
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns></returns>
        public string Sha512(string filePath)
        {
            using var stream = File.OpenRead(filePath);
            return Sha512(stream);
        }
        
        /// <summary>
        /// Generate SHA512 hash from a given stream.
        /// </summary>
        /// <param name="stream"></param>
        /// <returns></returns>
        public string Sha512(Stream stream)
        {
            var result = default(string);

            using var algo = System.Security.Cryptography.SHA512.Create();
            result = GenerateHashFromStream(algo, stream);
            
            return result;
        }
    }
}
