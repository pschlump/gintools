
const imageUrl = "https://.../image.jpg";

fetch(imageUrl)
  //                         vvvv
  .then(response => response.blob())
  .then(imageBlob => {
      // Then create a local URL for that image and print it
      const imageObjectURL = URL.createObjectURL(imageBlob);
      console.log(imageObjectURL);
  });
