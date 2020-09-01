using LdapForNet;
using Xunit;

namespace LdapForNetTests
{
	public class DirectoryEntryTests
	{
		[Theory]
		[InlineData("objectSid", new byte[] { 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0xB0, 0x68, 0x77, 0x23, 0x28, 0xE5, 0x17, 0xDF, 0xDE, 0x78, 0x25, 0x94, 0x86, 0x13, 0x00, 0x00 })]
		public void DirectoryEntry_Convert_Binary_Attributes_From_LdapEntry(string attributeName, byte[] attributeValue)
		{
			// Prepare directory attribute.
			var attribute = new DirectoryAttribute {Name = attributeName};
			attribute.Add(attributeValue);

			// Prepare directory entry.
			var entry = new DirectoryEntry {Attributes = new SearchResultAttributeCollection {attribute}};

			// Convert DirectoryEntry to LdapEntry and then back to DirectoryEntry.
			entry = entry.ToLdapEntry().ToDirectoryEntry();
			attribute = entry.GetAttribute(attributeName);

			// Assert.
			Assert.Equal(attributeName, attribute.Name);
			Assert.Equal(attributeValue, attribute.GetValue<byte[]>());
        }

		[Fact]
		public void DirectoryEntry_GetObjectSid_Return_Sid_In_String_Format()
		{
			// Arrange
			var attribute = new DirectoryAttribute { Name = "objectSid" };
			attribute.Add(new byte[] { 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0xB0, 0x68, 0x77, 0x23, 0x28, 0xE5, 0x17, 0xDF, 0xDE, 0x78, 0x25, 0x94, 0x86, 0x13, 0x00, 0x00 });
			var entry = new DirectoryEntry { Attributes = new SearchResultAttributeCollection { attribute } };

			//Act
			var objectSid = entry.GetObjectSid();

			//Assert
			Assert.Equal("S-1-5-21-595028144-3742885160-2485483742-4998", objectSid);
		}
	}
}
