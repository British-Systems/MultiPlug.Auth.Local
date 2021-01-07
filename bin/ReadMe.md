# Creating a new .nupkg file

* Update AssemblyInfo.cs with new version numbers
* Build Release in Visual Studio
* Update MultiPlug.Auth.Local.nuspec with new version numbers
* Run nuget pack Nuget/MultiPlug.Auth.Local.nuspec
* Upload it to https://www.nuget.org/ manually