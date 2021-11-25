import os
import scrapy


class NeuropilCrawler(scrapy.Spider):
    
    name = 'neuropil_test_crawler'
    start_urls = ['https://nlnet.nl/thema/NGIZeroDiscovery.html', 'https://neuropil.org', 'https://www.neuropil.io']
    depth = 0

    def parse(self, response):    
        page = response.url[8:]
        print(page, response.headers, response.meta)

        try:
            os.mkdir('neuropil_crawl')
        except FileExistsError as fee:
            pass

        filename = os.path.join('neuropil_crawl', page.replace('/', '#')) # '%s' % '-'.join([str(elem) for elem in page])

        with open(filename, 'wb') as f:
            for text in response.xpath("//text()").getall():
                raw_text = text.replace('\n', '').strip()
                self.log('line ({length}): {text}'.format(length=len(raw_text), text=raw_text) )
                if (len(raw_text) > 0):
                    f.write(text.encode())
                    f.write(b'\n')

        self.log('Saved file %s' % filename)

        if self.depth < 2:
            selector = response.css('a::attr(href)').extract()
            for page in selector:
                # print (page)
                next_page = response.urljoin(page)
                # print (next_page)
                self.depth += 1
                yield scrapy.Request(next_page, callback=self.parse)
                self.depth -= 1
