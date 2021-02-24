using System;
using System.Xml.Serialization;

namespace MultiPlug.Auth.Local.Models
{
    [Serializable]
    [XmlRoot(ElementName = "MultiPlug.Auth.Local")]
    public class AuthLocalFile
    {
        [XmlIgnore]
        public bool isLegacy { get; set; }

        [XmlArray("users")]
        [XmlArrayItem("add")]
        public User[] Users { get; set; }

        [XmlArray("Users")]
        [XmlArrayItem("User")]
        public User[] UsersLegacy { get { return this.Users; } set { this.Users = value; isLegacy = true; } }
    }

    public class User
    {
        [XmlAttribute("username")]
        public string Username { get; set; }
        [XmlAttribute("Username")]
        public string UsernameLegacy { get { return this.Username; } set { this.Username = value; } }
        [XmlAttribute("password")]
        public string Password { get; set; }
        [XmlAttribute("Password")]
        public string PasswordLegacy { get { return this.Password; } set { this.Password = value; } }
        [XmlAttribute("enabled")]
        public bool Enabled { get; set; }
        [XmlAttribute("Enabled")]
        public bool EnabledLegacy { get { return this.Enabled; } set { this.Enabled = value; } }
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
