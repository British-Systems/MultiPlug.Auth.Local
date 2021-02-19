using System;
using System.Xml.Serialization;

namespace MultiPlug.Auth.Local.Models
{
    [Serializable]
    [XmlRoot(ElementName = "MultiPlug.Auth.Local")]
    public class AuthLocalFile
    {
        [XmlArray("users")]
        [XmlArrayItem("add")]
        public User[] Users { get; set; }
    }

    public class User
    {
        [XmlAttribute("username")]
        public string Username { get; set; }
        [XmlAttribute("password")]
        public string Password { get; set; }
        [XmlAttribute("enabled")]
        public bool Enabled { get; set; }
        [XmlArray("tokens")]
        [XmlArrayItem("add")]
        public Token[] Tokens { get; set; }
    }

    public class Token
    {
        [XmlAttribute("token")]
        public string Value { get; set; }
        [XmlAttribute("expiry")]
        public string Expiry { get; set; }
    }
}
