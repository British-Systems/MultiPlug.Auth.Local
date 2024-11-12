using System;
using System.IO;
using System.Linq;
using System.Xml.Serialization;
using System.Collections.Generic;
using MultiPlug.Auth.Local.Models.File;

namespace MultiPlug.Auth.Local.File
{
    internal static class FileManager
    {
        private const string m_AuthFile = "MultiPlug.Auth.Local.config";

        internal static void Write(FileBody theFileObject)
        {
            XmlAttributeOverrides overrides = new XmlAttributeOverrides();

            XmlAttributes attribs = new XmlAttributes();
            attribs.XmlIgnore = true;
            attribs.XmlElements.Add(new XmlElementAttribute("UsersLegacy"));
            overrides.Add(typeof(FileBody), "UsersLegacy", attribs);

            attribs = new XmlAttributes();
            attribs.XmlIgnore = true;
            attribs.XmlElements.Add(new XmlElementAttribute("UsernameLegacy"));
            overrides.Add(typeof(FileUser), "UsernameLegacy", attribs);

            attribs = new XmlAttributes();
            attribs.XmlIgnore = true;
            attribs.XmlElements.Add(new XmlElementAttribute("PasswordLegacy"));
            overrides.Add(typeof(FileUser), "PasswordLegacy", attribs);

            attribs = new XmlAttributes();
            attribs.XmlIgnore = true;
            attribs.XmlElements.Add(new XmlElementAttribute("EnabledLegacy"));
            overrides.Add(typeof(FileUser), "EnabledLegacy", attribs);

            try
            {
                XmlSerializer Serializer = new XmlSerializer(typeof(FileBody), overrides);
                using (Stream stream = new FileStream(m_AuthFile, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    Serializer.Serialize(stream, theFileObject);
                }
            }
            catch { }
        }

        internal static FileBody Read()
        {
            try
            {
                XmlSerializer Serializer = new XmlSerializer(typeof(FileBody));
                using (Stream stream = new FileStream(m_AuthFile, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    var Content = (FileBody)Serializer.Deserialize(stream);

                    if (Content.Users == null)
                    {
                        Content.Users = new FileUser[0];
                    }
                    return Content;
                }
            }
            catch
            {
                return new FileBody { isLegacy = false, Users = new FileUser[0] };
            }
        }

        internal static void AddUser(FileBody theFile, FileUser theNewUser)
        {
            var Users = theFile.Users.ToList();
            Users.Add(theNewUser);
            theFile.Users = Users.ToArray();
        }

        internal static void DeleteUser(FileBody theFile, FileUser theNewUser)
        {
            var Users = theFile.Users.ToList();
            Users.Remove(theNewUser);
            theFile.Users = Users.ToArray();
        }

        internal static void AddTokens(FileUser theUser, FileToken[] theNewTokens)
        {
            List<FileToken> CurrentTokens = theUser.Tokens == null ? new List<FileToken>() : theUser.Tokens.ToList();
            CurrentTokens.AddRange(theNewTokens);
            theUser.Tokens = CurrentTokens.ToArray();
        }

        internal static bool RemoveTokens(FileUser theUser, string[] theRemovedTokens)
        {
            var TokensList = theUser.Tokens.ToList();

            foreach (var FriendlyName in theRemovedTokens)
            {
                var TokenSearch = TokensList.FirstOrDefault(Token => Token.FriendlyName != null && Token.FriendlyName.Equals(FriendlyName, StringComparison.OrdinalIgnoreCase));

                if (TokenSearch != null)
                {
                    TokensList.Remove(TokenSearch);
                }
                else
                {
                    return false;
                }
            }

            theUser.Tokens = TokensList.ToArray();

            return true;
        }

        internal static bool Exists()
        {
            return System.IO.File.Exists(m_AuthFile);
        }
    }
}
