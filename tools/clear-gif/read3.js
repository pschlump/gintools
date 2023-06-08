
async function load_pic() {

        const url = '<REPLACE-WITH-URL>'

        const options = {
            method: "GET"
        }

        let response = await fetch(url, options)

        if (response.status === 200) {

            const imageBlob = await response.blob()
            const imageObjectURL = URL.createObjectURL(imageBlob);

            const image = document.createElement('img')
            image.src = imageObjectURL

            const container = document.getElementById("your-container")
            container.append(image)
        }
        else {
            console.log("HTTP-Error: " + response.status)
        }
    }
