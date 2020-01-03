using System;
using System.Xml.Serialization;

namespace MultiPlug.Auth.Local.Models
{
    [Serializable]
    [XmlRoot(ElementName = "MultiPlug.Auth.Local")]
    public class AuthLocalFile
    {
        [XmlArrayItem("User")]
        public User[] Users { get; set; }
    }

    public class User
    {
        [XmlAttribute]
        public bool Enabled { get; set; }
        [XmlAttribute]
        public string Username { get; set; }
        [XmlAttribute]
        public string Password { get; set; }
    }
}
