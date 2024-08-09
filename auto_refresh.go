package jwksclient

import "time"

func (c *Client) autoRefresh() {
	log.Info().Msgf("starting auto refresh every %s", c.autoRefreshInterval)

	defer func() {
		if c.wg != nil {
			c.wg.Done()
		}

		log.Info().Msg("auto refresh stopped")
	}()

	tick := time.NewTicker(c.autoRefreshInterval)
	defer tick.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return

		case <-tick.C:
			refreshed, err := c.refresh()
			if err != nil {
				log.Error().Err(err).Msg("error refreshing JWKS")
				return
			}

			if refreshed && c.rcb != nil {
				ks, err := c.GetKeySet()
				if err != nil {
					log.Error().Err(err).Msg("error getting key set")
				}

				c.rcb(ks, err)
			}
		}
	}
}
