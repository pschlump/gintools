
//  See: https://thewebdev.info/2021/10/12/how-to-get-an-image-from-api-with-javascript-fetch-api/
//

const imageUrl = "https://picsum.photos/200/300";

const reader = new FileReader();
reader.onloadend = () => {
  const base64data = reader.result;
  console.log(base64data);
}

(async () => {
  const response = await fetch(imageUrl)
  const imageBlob = await response.blob()
  reader.readAsDataURL(imageBlob);
})()
