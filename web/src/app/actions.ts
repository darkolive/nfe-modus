"use server"

type FetchQueryProps = {
  query: string
  variables?: Record<string, unknown>
  credentials?: RequestCredentials
}

/**
 * Central function for making GraphQL queries to the Modus backend
 */
export const fetchQuery = async ({ query, variables, credentials = 'same-origin' }: FetchQueryProps) => {
  try {
    const res = await fetch(
      process.env.HYPERMODE_API_ENDPOINT || "http://localhost:8686/graphql",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ query, variables }),
        cache: "no-store",
        credentials,
      },
    )

    if (!res.ok) throw new Error(res.statusText)

    const { data, errors } = await res.json()
    if (errors) throw new Error(JSON.stringify(errors))

    return { data }
  } catch (err) {
    console.error("Error in fetchQuery:", err)
    return { data: null, error: err }
  }
}
